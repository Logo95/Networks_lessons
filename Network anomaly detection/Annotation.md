# Аннотация работы приложения "Система обнаружения сетевых аномалий"

## Общее описание
"Система обнаружения сетевых аномалий" предназначена для захвата сетевых пакетов, анализа их на наличие аномалий и эмуляции атак для тестирования системы.

## Архитектура системы
Архитектура приложения состоит из следующих компонентов:
- Захват сетевых пакетов.
- Анализ пакетов.
- Эмуляция атак.
- Логирование результатов.

## Основные алгоритмы

### Захват сетевых пакетов
Алгоритм захвата сетевых пакетов использует библиотеку Scapy для прослушивания указанного сетевого интерфейса и захвата всех проходящих пакетов.

#### Диаграмма последовательности для захвата сетевых пакетов
```plantuml
@startuml
actor User
User -> Application : Запуск приложения
Application -> Scapy : Инициализация захвата на интерфейсе
Scapy -> Application : Возвращает захваченные пакеты
Application -> User : Отображение захваченных пакетов
@enduml
```

#### Диаграмма последовательности для анализа пакетов
```plantuml
@startuml
actor User
User -> Application : Захват пакетов
Application -> Analyzer : Отправка пакетов на анализ
Analyzer -> Rules : Проверка правил
Rules -> Analyzer : Возвращает результаты проверки
Analyzer -> Application : Отправка результатов анализа
Application -> User : Отображение результатов анализа
@enduml
```

#### Диаграмма последовательности для эмуляции атаки с фрагментацией IP
```plantuml
@startuml
actor User
User -> Application : Запуск эмуляции атаки
Application -> PacketGenerator : Генерация фрагментированных пакетов
PacketGenerator -> Network : Отправка пакетов
Application -> User : Отображение статуса атаки
@enduml
```

#### Диаграмма классов
```plantuml
@startuml
class PacketCapture {
    + start_packet_capture(interface: str, stop_event: threading.Event): void
    - packet_callback(packet): void
    - detect_ip_fragmentation(packet): void
}

class IPFragmentationAttack {
    + emulate_ip_fragmentation_attack(target_ip: str, packet_count: int = 10): void
}

class Main {
    + main(interface: str, target_ip: str, packet_count: int): void
}

PacketCapture --> IPFragmentationAttack : uses >
Main --> PacketCapture : uses >
Main --> IPFragmentationAttack : uses >
@enduml

```
#### Диаграмма последовательностей для захвата и анализа пакетов с последующим отобраением
```plantuml
@startuml
actor User
User -> Application : Запуск захвата пакетов
Application -> Scapy : Захват пакетов на интерфейсе
Scapy -> Application : Пакеты захвачены
Application -> PacketAnalyzer : Анализ пакетов
PacketAnalyzer -> Application : Результаты анализа
Application -> User : Отображение результатов
@enduml
```