В таблице с донорами появилась вот такая плашка.  
![image](https://github.com/user-attachments/assets/fb832d90-889c-4403-bd78-9439575817d2)


Какие-то из доменов попали в базу фишинга/malware и т.п. Захотелось найти эти домены.

Ручками проверить можно тут - https://transparencyreport.google.com/safe-browsing/search?url=riverbum.com

Быстрое гугление готового сервиса, чтобы массово проверить, ничего не дало (мб плохо гуглил). Посмотрел запросы https://transparencyreport.google.com, увидел адрес API (который используется в самом сервисе, в Google Cloud есть свои API-методы, но у меня нет API KEY для Google Cloud, попросил AIшку накидать скрипт.

Код - https://github.com/sc00d/safe-browsing-google-free-bulk-checker

Я запускаю в Jupiter Notebook. В папке со скриптом нужно создать файл domains.txt откуда скрипт будет брать домены для проверки. В консоли можно следить за выполнением. По окончанию проверки создастся файл dangerdomains.txt со списком плохих доменов.

![image](https://github.com/user-attachments/assets/ed349809-242b-4463-a450-4df4c42cf452)


Может быть полезен при отборе доноров или отборе дропов.

Автор https://t.me/sc00d, канал - https://t.me/seregaseo 
