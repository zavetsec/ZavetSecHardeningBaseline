================================================================================
  ZavetSec | HardeningBaseline v1.0
  Базовое усиление защиты Windows -- Краткое руководство (Русский)
  https://github.com/zavetsec
================================================================================

ОПИСАНИЕ
--------
ZavetSecHardeningBaseline -- скрипт PowerShell 5.1 для аудита и применения
настроек усиления безопасности Windows на рабочих станциях и серверах.
Покрывает требования CIS Benchmark L1/L2, DISA STIG и Microsoft Security
Baseline с привязкой к техникам MITRE ATT&CK. Поддерживает как интерактивную
работу через BAT-лаунчер, так и массовое развёртывание через PsExec,
планировщик задач или пайплайны автоматизации.

ФАЙЛЫ
-----
  ZavetSecHardeningBaseline.ps1   Основной скрипт
  Run-Hardening.bat               Интерактивный лаунчер с меню (рекомендуется
                                  для ручного запуска на отдельных машинах)

БЫСТРЫЙ СТАРТ
-------------

  СПОСОБ 1 -- BAT-ЛАУНЧЕР (рекомендуется для ручного запуска)
  -------------------------------------------------------------
  Правая кнопка на Run-Hardening.bat -> "Запуск от имени администратора"

  Появляется меню:
    [1] AUDIT    -- проверка текущего состояния, без изменений
    [2] APPLY    -- применить все настройки усиления
    [3] ROLLBACK -- восстановить предыдущее состояние из резервной копии
    [4] EXIT

  Лаунчер автоматически:
    - Проверяет наличие прав Администратора перед запуском
    - Создаёт папку Reports\ рядом со скриптами
    - Сохраняет HTML-отчёты и JSON-резервные копии с временными метками
    - Предлагает открыть HTML-отчёт в браузере после каждого запуска
    - В режиме ROLLBACK: показывает список резервных копий с номерами,
      ввод пути вручную не требуется

  СПОСОБ 2 -- POWERSHELL НАПРЯМУЮ
  ---------------------------------
  # Только аудит (без изменений)
  .\ZavetSecHardeningBaseline.ps1 -Mode Audit

  # Применить усиление (с запросом подтверждения)
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply

  # Применить без запросов (PsExec / планировщик / автоматизация)
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply -NonInteractive

  # Применить с явным указанием путей
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply `
      -OutputPath C:\Reports\hardening.html `
      -BackupPath C:\Reports\backup.json

  # Откат изменений
  .\ZavetSecHardeningBaseline.ps1 -Mode Rollback `
      -BackupPath .\Reports\HardeningBackup_20260318_120000.json

  # Частичное применение -- пропустить отдельные разделы
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipAuditPolicy
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipNetworkHardening
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipCredentialProtection
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipPowerShell

  # Защита от PrintNightmare -- отключение Print Spooler (опционально)
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply -EnablePrintSpoolerDisable

  СПОСОБ 3 -- МАССОВОЕ РАЗВЁРТЫВАНИЕ ЧЕРЕЗ PSEXEC
  -------------------------------------------------
  psexec \\TARGET -s -c .\ZavetSecHardeningBaseline.ps1 -Mode Apply -NonInteractive

ВОЗМОЖНОСТИ
-----------
  Сетевая защита              (NET-001 -- NET-010)
    - Отключение LLMNR, mDNS, WPAD, NBT-NS, LMHOSTS
    - Отключение SMBv1 (сервер + клиентский драйвер)
    - Обязательная подпись SMB (сервер + клиент)
    - Ограничение анонимного перечисления SAM и шар
    - Отключение службы Remote Registry

  Защита учётных данных       (CRED-001 -- CRED-006)
    - Отключение кэширования паролей WDigest (защита от Mimikatz)
    - Включение LSA Protection (RunAsPPL)
    - Включение Windows Defender Credential Guard (VBS)
    - Принудительное использование только NTLMv2
    - Запрет хранения LM-хэшей
    - Требование 128-битной защиты сессии NTLM

  Защита PowerShell           (PS-001 -- PS-005)
    - Включение Script Block Logging (событие 4104)
    - Включение Module Logging (событие 4103)
    - Включение транскрипции в C:\ProgramData\PSTranscripts
    - Отключение движка PowerShell v2 (вектор обхода AMSI)
    - Установка Execution Policy в RemoteSigned (уровень машины)

  Политика аудита             (AUD-001 -- AUD-027)
    - 27 подкатегорий через auditpol (по GUID, независимо от языка ОС)
    - Охват: Вход/Выход, Kerberos, Создание процессов, Управление учётками,
      Доступ к объектам, Привилегии, Изменение политик, DPAPI,
      Запланированные задачи, Съёмные носители, События брандмауэра и др.

  Системная защита            (SYS-001 -- SYS-010)
    - Включение UAC с полным контролем (запрос на защищённом рабочем столе)
    - Отключение AutoRun/AutoPlay для всех типов дисков
    - Включение брандмауэра Windows на всех профилях
    - Требование NLA для подключений RDP
    - Включение DEP для всех программ
    - Журнал Security: 1 ГБ, перезапись (без архивных файлов)
    - Политика DNS over HTTPS
    - Высокий уровень шифрования RDP
    - Опционально: отключение Print Spooler (PrintNightmare)

РЕЖИМЫ
------
  Audit     Только проверка. Без изменений. Генерирует HTML-отчёт.
  Apply     Применяет все настройки. Создаёт JSON-резервную копию.
  Rollback  Восстанавливает из файла резервной копии.

РЕЗУЛЬТАТЫ РАБОТЫ
-----------------
  HTML-отчёт  : Тёмная тема, брендинг ZavetSec, фильтрация
                Уровень критичности, MITRE, команды исправления по каждому пункту
  JSON-бэкап  : Сохраняется перед любым Apply; используется режимом Rollback

  Расположение:
    Через Run-Hardening.bat   -> .\Reports\ (создаётся автоматически)
    Через PowerShell напрямую -> каталог скрипта (или -OutputPath / -BackupPath)

ТРЕБОВАНИЯ
----------
  PowerShell : 5.1+
  ОС         : Windows 10/11, Windows Server 2016/2019/2022
  Права      : Локальный Администратор (для режимов Apply и Rollback)
  Перезагрузка: Требуется для Credential Guard, DEP, отключения PSv2 и SMBv1

================================================================================
  ZavetSec -- Лицензия MIT -- https://github.com/zavetsec
================================================================================
