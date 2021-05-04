## Описание
Коннектор к PTSIEM
Собирает инциденты и события, относящиесяк ним, пересылает в nxlog

## Зависимости
- pip install -r requirements.txt
- pip install [socutils]


## /appconfig/ptconnector-setting.yaml

```
sentry_url:
logging:
  basic_level: INFO
  term_level: DEBUG
  file_level: DEBUG
  sentry_level: WARNING

mongodb:
  host: localhost
  port: 27017
  dbname: ptconnect

first_start_flashback: 720 #minutes отступ по времени для первоначального сбора
indent_time: 30 #minutes дополнительный отступ назад по времени
timeout: 1 #minutes

pt:
  core_host: mpsiem_test.org
  core_user: login
  core_pass: password

#incident_names: soc_%  # можно вместо списка указать шаблон интересующих имён инцидентов
incident_names: # если список пуст - собираем все инциденты
  - Soc_0001
  - Soc_0002
  - Soc_auth

nxlog:
  host: 127.0.0.1
  port: 12000

nxlog_attributes:
  SeverityValue: 1
  Severity: INFO
  Organization: org
  OrgID: 2
  DevCat: security
  DevSubCat: unicon
  DevType: ptsiem
  DevVendor: vendor_org

proxy:
  http:
  https:

telegram:
  enable: False
  chat_id: 
  token: 

```