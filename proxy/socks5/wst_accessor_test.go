package socks5

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/nixavpn/shadowlink/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nopStream — пустышка client.StreamTransport для проверок доступа к полю.
type nopStream struct{ id int }

func (n *nopStream) WriteMessage([]byte) error                         { return nil }
func (n *nopStream) StartReader(context.Context, *client.Client) error { return nil }
func (n *nopStream) Close() error                                      { return nil }

var _ client.StreamTransport = (*nopStream)(nil)

// TestServer_WSTFieldIsUnexported — сторож дефекта №2.
//
// Суть дефекта: поле WST было ПУБЛИЧНЫМ и читалось из другого пакета (engine)
// на каждый CONNECT, а переписывалось на лету при реконнекте. Мьютекс в engine/
// такую гонку закрыть не мог физически — читатели живут здесь. Единственная
// защита, которую нельзя обойти извне, — сделать поле неэкспортируемым.
//
// Тест смотрит на структуру рефлексией, а не на поведение: поведенческая
// проверка осталась бы зелёной и после того, как кто-нибудь вернёт публичное
// поле «для удобства», а вместе с ним и гонку.
func TestServer_WSTFieldIsUnexported(t *testing.T) {
	st := reflect.TypeOf(Server{})

	_, hasExported := st.FieldByName("WST")
	assert.False(t, hasExported,
		"поле WST обязано остаться неэкспортируемым: публичное поле читается из другого пакета на каждый CONNECT и переписывается реконнектом — гонка между пакетами")

	f, ok := st.FieldByName("wst")
	require.True(t, ok, "приватное поле wst должно существовать")
	assert.Equal(t, reflect.TypeOf((*client.StreamTransport)(nil)).Elem(), f.Type)
}

// TestServer_WSTAccessorsRoundTrip — базовая власть аксессоров: сеттер
// действительно виден геттеру. Без этого предыдущий тест был бы зелёным и на
// нерабочей паре методов.
func TestServer_WSTAccessorsRoundTrip(t *testing.T) {
	s := &Server{}
	assert.Nil(t, s.WST(), "до установки транспорт обязан быть nil (poll-mode)")

	a := &nopStream{id: 1}
	s.SetWST(a)
	assert.Same(t, a, s.WST())

	b := &nopStream{id: 2}
	s.SetWST(b)
	assert.Same(t, b, s.WST(), "переустановка обязана быть видна читателям")

	s.SetWST(nil)
	assert.Nil(t, s.WST(), "nil обязан приниматься: это штатный переход в poll-mode")
}

// TestServer_WSTConcurrentSwapIsSerialized — нагрузочная проверка аксессоров под
// параллельными записями: геттер обязан всегда возвращать ОДИН ИЗ записанных
// объектов и никогда nil или чужой тип.
//
// ⚠ ЧЕСТНО О ВЛАСТИ ЭТОГО ТЕСТА, иначе он станет зелёным сторожем, который ничего
// не измеряет. Власть проверена порчей 2026-08-24: если снять мьютекс с WST() и
// SetWST(), тест ОСТАЁТСЯ ЗЕЛЁНЫМ. На amd64 запись пары слов интерфейса на
// практике не рвётся, а -race на Windows недоступен (hard rule 6) — то есть
// поймать отсутствие лока этим способом нельзя в принципе.
//
// Поэтому доказательство защищённости несёт НЕ он, а
// TestServer_WSTFieldIsUnexported: приватность поля — единственное свойство,
// которое проверяемо и которое физически не даёт другому пакету обойти
// синхронизацию. Этот тест остаётся как проверка того, что аксессоры не портят
// значение под нагрузкой, и не более того.
func TestServer_WSTConcurrentSwapIsSerialized(t *testing.T) {
	s := &Server{}
	const writers = 4
	const iterations = 2000

	streams := make([]*nopStream, writers)
	valid := map[int]bool{}
	for i := range streams {
		streams[i] = &nopStream{id: i + 1}
		valid[i+1] = true
	}
	s.SetWST(streams[0])

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s.SetWST(streams[idx])
			}
		}(i)
	}

	for i := 0; i < iterations; i++ {
		got := s.WST()
		require.NotNil(t, got, "читатель не должен видеть nil: nil никто не писал")
		ns, ok := got.(*nopStream)
		require.True(t, ok, "читатель получил значение чужого типа — интерфейс порван")
		require.True(t, valid[ns.id], "читатель получил неизвестный id %d — интерфейс порван", ns.id)
	}

	close(stop)
	wg.Wait()
}

// TestDialUDP_NilTransportReturnsErrorNotPanic — nil-семантика на data-path.
//
// Переход на аксессор обязан сохранить поведение «транспорта нет → ошибка», а не
// паниковать: в основном режиме десктопа этот путь исполняется на каждый
// UDP-поток. Спека прямо предупреждала об этой ловушке — при провайдере-функции
// nil-семантика раздваивалась бы (nil-функция и nil-результат), и пропуск любой
// из проверок давал бы панику именно здесь.
//
// Клиент подставляется НАСТОЯЩИЙ и подключённый — иначе проверка `Client == nil`
// сработала бы раньше и тест ничего не сказал бы о транспорте (проверено
// порчей: с nil-клиентом снятие nil-проверки транспорта оставляет тест зелёным).
func TestDialUDP_NilTransportReturnsErrorNotPanic(t *testing.T) {
	cl := setupConnectedClient(t)

	srv := &Server{Client: cl} // транспорт НЕ установлен → poll-mode
	require.Nil(t, srv.WST())

	d := newInProcessDialer(context.Background(), srv)

	require.NotPanics(t, func() {
		pc, err := d.DialUDP(metaFor("8.8.8.8", 53))
		assert.Nil(t, pc)
		assert.Error(t, err, "без транспорта DialUDP обязан вернуть ошибку, а не панику")
	})
}
