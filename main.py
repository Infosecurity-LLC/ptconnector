import logging
import os
import time
import urllib3
import requests
from socutils import NXLogSender
from urllib3.exceptions import InsecureRequestWarning
from modules.ptclient import PTClient
from modules.environment import setting
from modules.db import Mongo
from datetime import datetime, timedelta

urllib3.disable_warnings(InsecureRequestWarning)

current_dir = os.path.abspath(os.path.dirname(__file__))
os.chdir(current_dir)

# LOGGING #########
logging.basicConfig(level=setting['logging']['basic_level'],
                    format='%(asctime)s - %(levelname)-10s - [in %(filename)s:%(lineno)d]: - %(message)s')
logger = logging.getLogger('pt_connector')
logger.setLevel(setting['logging']['term_level'])
logger.info('PT_Connector will be started')


def sleep():
    """Время в минутах """
    stime = setting['timeout']
    logger.info(f"Sleep {stime} m")
    time.sleep(abs(stime * 60))


class PTConnector:
    def __init__(self, settings):
        self.settings = settings
        self.pt_client = PTClient(self.settings.get('pt'))
        self.nxlog = NXLogSender(self.settings['nxlog'].get('host'),
                                 self.settings['nxlog'].get('port'))
        self.mongo = Mongo(self.settings.get('mongodb'))
        self.mongo.create_index(fields='id', collection='incidents', unique=True)
        self.lp_id = None

    def get_start_time(self):
        """
        Получаем время старта последней успершной итерации сбора событий
        :return:
        """
        lp, lp_id = self.mongo.get_last_position(self.settings['mongodb']['dbname'],
                                                 self.settings['first_start_flashback'])
        lp = datetime.fromtimestamp(lp) - timedelta(minutes=setting.get('indent_time'))
        logger.info(f"Last position {lp}")
        lp = lp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        self.lp_id = lp_id
        return lp

    def confirm_successful_parsing(self):
        """
        Подтверждаем успешность итерации сбора событий и записывам время окончания работы
        :return:
        """
        self.mongo.update_last_end_time(self.lp_id)

    def get_incidents(self, start_time):
        """
        Собираем события
        :param start_time:
        :return:
        """

        def inc_in_db(inc_id):
            """
            Проверяем, есть ли такой инцидент в базе
            :param inc_id:
            :return:
            """
            return bool(self.mongo.get_query_filter(filter_={"id": inc_id}, collection="incidents", count=True))

        def get_inc_more_info(inc_id):
            """ Получаем расширенную информацию по инциденту """
            return self.pt_client.get_incident(inc_id)

        def reformat_event(event_d: dict):
            """
            Рекурсивная замена точек в ключах на '_' (в списки не лезем, в конкретном случае нет необходимости)
            Монга не любит точки в ключах
            :param event_d:
            :return:
            """
            new_dict = {}

            def rename(name):
                return name.replace(".", "_")

            def update(k, v):
                if isinstance(v, dict):
                    new_dict.update({k: reformat_event(v)})
                else:
                    new_dict.update({k: v})

            for key, value in event_d.items():
                if '.' in key:
                    new_key_name = rename(key)
                    update(new_key_name, value)
                else:
                    update(key, value)
            return new_dict

        def get_events(inc_id):
            """"""
            return [reformat_event(event) for event in self.pt_client.get_events(inc_id)]

        incidents = self.pt_client.get_incidents(time_from=start_time,
                                                 incident_names=self.settings.get('incident_names'))
        if not isinstance(incidents, list) and not incidents:
            return False
        for inc in incidents:

            if inc_in_db(inc['id']):
                logger.debug(f"Инцидент {inc['key']} уже есть в базе")
                continue
            logger.debug(f"Получаю данные по инциденту {inc['key']} id: {inc['id']}")
            inc = {**inc, **get_inc_more_info(inc['id'])}
            logger.info(f"Получаю события по {inc['key']} [{inc['name']}] id: {inc['id']}")
            inc_events = get_events(inc['id'])
            inc.update(dict(events=inc_events, _status=0, _status_tg=0))
            inc.update(dict(vendor_product_version=self.pt_client.pt_version))
            self.mongo.insert_document(inc, collection='incidents')

    def close_incidents(self, incidents):
        for inc in incidents:
            self.pt_client.change_incident_status(inc)

    def send(self):
        def send_to_nxlog():
            """
            Отправка собранных событий в NXLog
            :return:
            """

            def nxlog_formater(message):
                """ Форматируем событие для nxlog'a """

                def md5_from_raw(raw):
                    import hashlib
                    hash_t = hashlib.md5()
                    hash_t.update(str(raw).encode('utf8'))
                    return hash_t.hexdigest()

                if 'created' in message:
                    it = message['created']
                    incident_time = datetime.now().astimezone().isoformat()
                else:
                    logger.error(f"Не смогли распарсить время incident_id: {message['id']} {message}")
                    return False
                new_event = {
                    "IncidentTime": incident_time,
                    "EventTime": incident_time,
                    "Hostname": setting['pt']['core_host'],
                    "Dvc": setting['pt']['core_host'],
                    "SeverityValue": setting['nxlog_attributes'].get('SeverityValue'),
                    "Severity": setting['nxlog_attributes'].get('Severity'),
                    "Organization": setting['nxlog_attributes'].get('Organization'),
                    "OrgID": setting['nxlog_attributes'].get('OrgID'),
                    "DevCat": setting['nxlog_attributes'].get('DevCat'),
                    "DevSubCat": setting['nxlog_attributes'].get('DevSubCat'),
                    "DevType": setting['nxlog_attributes'].get('DevType'),
                    "DevVendor": setting['nxlog_attributes'].get('DevVendor'),
                    "raw": message,
                    "md5": md5_from_raw(message)

                }
                return new_event

            sended_incidents = []
            incidents = self.mongo.get_query_filter(filter_={"_status": 0}, collection="incidents")
            self.nxlog.connect()
            logger.info(f"Start sending {len(incidents)} incidents to NXLog")
            for incident in incidents:
                event_for_nxlog = nxlog_formater(incident)
                if self.nxlog.send_event(event_for_nxlog):
                    # _id - id записи в базе
                    # id - -id инцидента
                    self.mongo.update_document({"_id": incident['_id']}, {"$set": {"_status": 1}},
                                               collection="incidents")
                    sended_incidents.append(dict(id=incident['id'], key=incident['key']))
            self.nxlog.close()
            return sended_incidents

        def send_to_telegram():
            """
            Отправка собранных событий в Telegram
            :return:
            """
            stg = self.settings.get('telegram')
            if not stg or not stg.get('enable'):
                # TG sending is disable
                return False

            def tg_formater(inc: dict):
                """
                Форматирование инцидента для телеги
                :param inc:
                :return: str
                """
                url = f"{self.settings['pt']['core_host']}/#/incident/incidents/view/{inc['id']}"
                severity_emoji = None
                if not inc.get('severity') or inc.get('severity') in ["Low", "Undefined"]:
                    severity_emoji = "\u26a0\ufe0f"
                elif inc.get('severity') == "Medium":
                    severity_emoji = "\u2757\ufe0f"
                elif inc.get('severity') == "High":
                    severity_emoji = "\u203c\ufe0f"

                msg = f'{severity_emoji} [{inc.get("key")}]({url}) [{inc.get("name")}]\n' \
                      f'`{inc.get("description")}`\n'
                return msg

            def send(message):
                """
                Отправка сообщения в телегу
                :param message:
                :return:
                """
                try:
                    r = requests.post("https://api.telegram.org/bot" + stg['token'] + "/sendMessage",
                                      data={'chat_id': stg['chat_id'], 'text': message, 'parse_mode': 'Markdown'},
                                      verify=False,
                                      proxies=self.settings['proxy'])
                    r.raise_for_status()
                except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as err:
                    logger.error(err)
                    return False
                time.sleep(0.3)
                return True

            def update(document_ids: list):
                """ помечаем события как отправленные"""
                self.mongo.update_documents({"_id": {"$in": document_ids}}, {"$set": {"_status_tg": 1}},
                                            collection="incidents")

            incidents = self.mongo.get_query_filter(filter_={"_status_tg": 0}, collection="incidents")
            logger.info(f"Start sending {len(incidents)} incidents to telegram")
            if not incidents:
                return
            message = ""
            sent = []
            for incident in incidents:

                fm = tg_formater(incident)
                if len(message + fm) < 4096:
                    message += fm
                    sent.append(incident['_id'])
                else:
                    if send(message):
                        update(sent)
                    sent = []
                    message = fm
                    sent.append(incident['_id'])
            if send(message):
                update(sent)

        send_to_nxlog()
        send_to_telegram()


def start():
    pt = PTConnector(setting)
    lp = pt.get_start_time()
    pt.get_incidents(start_time=lp)
    pt.confirm_successful_parsing()
    pt.send()
    sleep()


if __name__ == '__main__':
    while True:
        start()
