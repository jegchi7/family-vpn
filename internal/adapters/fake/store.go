// Package fake contains nonfunctional fixtures only. It never calls a VPN core.
package fake

import (
	"context"
	"familyvpn.local/platform/internal/domain"
	"time"
)

type Store struct {
	Devices []domain.Device
	Samples []domain.Health
}

func New(now time.Time) *Store {
	return &Store{
		Devices: []domain.Device{
			{ID: "dev-iphone", OwnerID: "demo-family", Revision: 1, Name: "Мой iPhone", OS: "ios", State: "active", Profiles: []domain.Profile{{ID: "p-awg", Protocol: "awg", State: "ready", Format: "txt"}, {ID: "p-reality", Protocol: "reality", State: "ready", Format: "txt"}}},
			{ID: "dev-laptop", OwnerID: "demo-family", Revision: 1, Name: "Ноутбук", OS: "windows", State: "partial", Profiles: []domain.Profile{{ID: "p-laptop", Protocol: "awg", State: "pending", Format: "txt"}}},
			{ID: "dev-other", OwnerID: "other-user", Revision: 1, Name: "Чужое устройство", OS: "android", State: "active", Profiles: []domain.Profile{{ID: "p-other", Protocol: "awg", State: "ready", Format: "txt"}}},
		},
		Samples: []domain.Health{
			{Component: "Вход на RU", Status: "healthy", Reason: "Тестовый результат, без сетевого измерения", MeasuredAt: now, ExpiresAt: now.Add(60 * time.Second)},
			{Component: "Выход в интернет", Status: "degraded", Reason: "Тестовый сценарий: используется резерв", MeasuredAt: now, ExpiresAt: now.Add(60 * time.Second)},
			{Component: "Проверка браузера", Status: "unknown", Reason: "Внешний probe ещё не подключён", MeasuredAt: now, ExpiresAt: now.Add(60 * time.Second)},
		},
	}
}
func (s *Store) Owned(owner string) []domain.Device {
	result := []domain.Device{}
	for _, d := range s.Devices {
		if d.OwnerID == owner {
			result = append(result, d)
		}
	}
	return result
}
func (s *Store) Profile(owner, id string) (domain.Profile, bool) {
	for _, d := range s.Owned(owner) {
		for _, p := range d.Profiles {
			if p.ID == id {
				return p, true
			}
		}
	}
	return domain.Profile{}, false
}
func Instructions() []domain.Instruction {
	return []domain.Instruction{
		{ID: "ios", OS: "ios", Title: "Подключение iPhone", Verified: false, Steps: []string{"Демонстрационная инструкция: подбор клиента ещё не проверен на реальном устройстве.", "В рабочей версии здесь будут проверенная ссылка установки и импорт основного профиля.", "Сразу сохраните резервный профиль и офлайн-памятку.", "Включите VPN в приложении, затем вернитесь к проверке. Браузер не включает VPN самостоятельно."}},
		{ID: "android", OS: "android", Title: "Подключение Android", Verified: false, Steps: []string{"Выберите приложение после проверки совместимости конкретной версии.", "Импортируйте отдельные основной и резервный профили своего устройства.", "Разрешите VPN-подключение в системном диалоге приложения.", "Проверьте соединение по Wi-Fi и мобильной сети; этот стенд не выполняет такую проверку."}},
		{ID: "windows", OS: "windows", Title: "Подключение Windows", Verified: false, Steps: []string{"Подготовьте основной и резервный профили для компьютера.", "Установите проверенную версию клиента и импортируйте профиль.", "Включите соединение и проверьте маршрут браузера.", "Не импортируйте файл из этого демо: он содержит только памятку, без VPN-ключей."}},
	}
}

func (s *Store) DevicesForOwner(_ context.Context, owner string) ([]domain.Device, error) {
	return s.Owned(owner), nil
}
func (s *Store) ProfileForOwner(_ context.Context, owner, id string) (domain.Profile, bool, error) {
	p, ok := s.Profile(owner, id)
	return p, ok, nil
}
func (s *Store) HealthSamples(context.Context) ([]domain.Health, error) { return s.Samples, nil }
func (s *Store) Instructions(context.Context) ([]domain.Instruction, error) {
	return Instructions(), nil
}
func (s *Store) DeviceCount(context.Context) (int, error) { return len(s.Devices), nil }
func (s *Store) Ping(context.Context) error               { return nil }
func (s *Store) Backend() string                          { return "memory-fixture" }
