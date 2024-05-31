# Постановка задач для разработки приложения "Система обнаружения сетевых аномалий"

## Введение
Этот документ описывает цели и требования для разработки системы обнаружения сетевых аномалий. Цель проекта - создать приложение, которое будет захватывать сетевые пакеты, анализировать их для обнаружения аномалий и эмулировать сетевые атаки для тестирования.

## Область применения
Проект включает захват и анализ сетевых пакетов, а также эмуляцию сетевых атак. Проект не включает создание GUI или работу с базами данных.

## Требования к функциональности
### Основные функции
- Захват сетевых пакетов с заданного интерфейса.
- Анализ пакетов для обнаружения сетевых аномалий.
- Эмуляция IP фрагментации для тестирования.

## Технические требования
- Язык программирования: Python
- Библиотеки: Scapy
- Совместимость: Linux и Windows

## Критерии успешности
- Программа успешно захватывает сетевые пакеты.
- Программа корректно анализирует пакеты и обнаруживает аномалии.
- Программа успешно эмулирует атаки с IP фрагментацией.

## Этапы разработки
1. Исследование и анализ:
   - Изучение необходимых библиотек и технологий.
2. Разработка:
   - Написание кода для захвата и анализа пакетов.
   - Написание кода для эмуляции атак.
3. Тестирование:
   - Проверка функциональности и производительности.
4. Внедрение:
   - Документация и публикация проекта.

## Риски и предположения
- Возможные сложности с совместимостью на разных операционных системах.
- Предположение, что библиотека Scapy будет поддерживаться и обновляться.
