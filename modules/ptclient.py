import requests
from requests.exceptions import ConnectionError
import re
import html
from datetime import datetime
import logging
import json
import sys
from typing import Dict

logger = logging.getLogger('pt_connector.pt_client')


class AccessDenied(Exception):
    pass


class BadResponseCode(Exception):
    pass


class BadServiceConfiguration(Exception):
    pass


class PTClient:
    def __init__(self, pt_setting):
        self.__setting = pt_setting
        self.host = f'https://{self.__setting.get("core_host")}'
        self.session = None
        self.__authenticate(self.host,
                            self.__setting.get("core_user"),
                            self.__setting.get("core_pass"))
        self.pt_version = self.get_siem_version()

    @staticmethod
    def __parse_form(data):
        return re.search('action=[\'"]([^\'"]*)[\'"]', data).groups()[0], {
            item.groups()[0]: html.unescape(item.groups()[1])
            for item in re.finditer('name=[\'"]([^\'"]*)[\'"] value=[\'"]([^\'"]*)[\'"]', data)
        }

    @staticmethod
    def print_response(response, expected_status: int = None, level: str = None):
        if level and not expected_status:
            logger.warning('Параметр level требует обязательного заполнения параметра expected_status')
        if expected_status and response.status_code != expected_status:
            if level == "critical":
                raise BadResponseCode(f'status_code: {response.status_code}, content: {response.text}')
            if level == "warning":
                logger.warning(f'PTSIEM вернул статус код отличный от {expected_status}: '
                               f'status_code: {response.status_code}, content: {response.text}')
            logger.error(f'PTSIEM вернул статус код отличный от {expected_status}: '
                         f'status_code: {response.status_code}, content: {response.text}')
            return False
        return response

    # authorization start
    # as is
    def __authenticate(self, address, login, password, new_password=None, auth_type=0):
        """
         Аутентификация в лоб
        :param address:
        :param login:
        :param password:
        :param new_password:
        :param auth_type:
        :return:
        """
        logger.debug("Подключаюсь к PTSIEM")
        self.session = requests.session()
        self.session.verify = False
        try:
            response = self.session.post(
                f'{address}:3334/ui/login',
                json=dict(
                    authType=auth_type,
                    username=login,
                    password=password,
                    newPassword=new_password
                )
            )
        except ConnectionError:
            logger.critical(f"Нет доступа к {address}:3334")
            sys.exit(1)

        # if response.status_code != 200:
        #     raise AccessDenied(response.text)

        if '"requiredPasswordChange":true' in response.text:
            raise AccessDenied(response.text)

        return self.__available_applications(address)

    def __available_applications(self, address):
        applications = self.print_response(
            self.session.get(f'{address}:3334/ptms/api/sso/v1/applications'),
            expected_status=200,
            level="critical").json()

        return [
            app['id']
            for app in applications
            if self.__is_application_available(app)
        ]

    def __is_application_available(self, app):
        if app['id'] == 'idmgr':
            modules = self.print_response(
                self.session.get(f"{app['url']}/ptms/api/sso/v1/account/modules"),
                expected_status=200,
                level="critical").json()
            return bool(modules)
        if app['id'] == 'mpx':
            return self.__external_auth(f"{app['url']}/account/login?returnUrl=/#/authorization/landing")

    def __external_auth(self, address):
        response = self.print_response(
            self.session.get(address),
            expected_status=200,
            level="critical")

        if 'access_denied' in response.url:
            return False

        while '<form' in response.text:
            form_action, form_data = self.__parse_form(response.text)

            response = self.print_response(
                self.session.post(form_action, data=form_data),
                expected_status=200,
                level="critical")
        return True

    # authorization end
    def get_incidents(self, time_from: int = None, time_to: int = None, incident_names=None, limit: int = 100):
        """
        Получаю все инциденты
        :param time_from: с какого времени начинать сбор данных
        :param time_to: по какое время
        :param limit: сколько элементов за раз получать без смещения
        :param incident_names: параметр выборки по имени
            * Если переменная это список имён инцидентов - будут возвращены только инциденты с этими именами
            * Если переменная равна None - будут возвращены все инциденты, незваисимо от имени
            * Если переманная типа str - имя инцидента будет матчиться по содержимому переменной
                (испольуется синтаксис PDQL! Пример: "soc_%" - вернёт все инциденты, имя которых начинается с soc_)
        :return: list
        """

        def get_incidents_pack(params):
            """
            Получаю список инцидентов
            :param params: Параметры для выдачи (запрос на PDQL)
            :return:
            """
            try:
                res = self.print_response(
                    self.session.post(f'{self.host}/api/v2/incidents/', json=params),
                    expected_status=200)
            except Exception as err:
                logger.error(f"Не могу собрать данные. Какая-то редкая ошибка {err}")
                return False
            if res is False:
                return False
            return res.text

        def make_query():
            """ Формирую поисковый запрос """
            query = {
                "filter": {
                    "orderby": [
                        {"field": "created", "sortOrder": "descending"},
                        {"field": "status", "sortOrder": "ascending"},
                        {"field": "severity", "sortOrder": "descending"}
                    ],
                    "select": ["key", "name", "category", "type", "status", "created", "assigned"],
                    "where": f'status != "Closed"'
                },
                "filterTimeType": "creation",
                "groups": {"filterType": "no_filter"},
                "limit": 100,
                "offset": 0,
                "queryIds": ["all_incidents"],
                "timeFrom": time_from,
                "timeTo": time_to}
            if incident_names and isinstance(incident_names, list):
                query['filter']['where'] = f'status != "Closed" and name in {incident_names}'

            if incident_names and isinstance(incident_names, str):
                query['filter']['where'] = f'status != "Closed" and match(name,"{incident_names}")'

            if incident_names and isinstance(incident_names, dict):
                for k, v in incident_names.items():
                    if k == "match":
                        query['filter']['where'] = f'status != "Closed" and match(name,"{v}")'
                    elif k == "contains":
                        query['filter']['where'] = f'status != "Closed" and (name contains "{v}")'
                    else:
                        raise BadServiceConfiguration('Некорректная конфигурация incident_names')
            return query

        if not time_from:
            logger.error('Не передано время старта сбора данных time_from')
            return []
        if not time_to:
            time_to = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

        all_incidents = []
        query = make_query()

        logger.info("Получаю инциденты")
        res = get_incidents_pack(query)
        if not res:
            logger.warning(f'При запросе инцидентов получили {res}')
            return all_incidents
        totalitems = json.loads(res).get('totalItems')
        logger.info(f"Обнаружено {totalitems}")
        if json.loads(res).get('message') == "Authorization has been denied for this request.":
            logger.error(json.loads(res))
            sys.exit(0)
        incidents = json.loads(res).get('incidents')
        if not incidents:
            return all_incidents
        all_incidents = all_incidents + incidents
        if totalitems > limit:
            for jump in range(1, round(totalitems / limit) + 1):
                logger.debug(f"Смещение {query['offset']} -> {jump * 100}")
                query['offset'] = jump * 100
                res = get_incidents_pack(query)
                incidents = json.loads(res).get('incidents')
                if not isinstance(incidents, list):
                    continue
                for inc in incidents:
                    if inc not in all_incidents:
                        all_incidents.append(inc)

        logger.debug(f"Получено {len(all_incidents)} инцидентов")
        return all_incidents

    def get_incident(self, inc_id):
        """
        Получают информацию по инциденту
        :param inc_id: id инцидента
        :return: dict
        """
        try:
            res = self.print_response(
                self.session.get(f'{self.host}/api/incidentsReadModel/incidents/{inc_id}'),
                expected_status=200)
        except Exception as err:
            logger.error(err)
            return {}
        if res is False:
            return {}
        return json.loads(res.text)

    def get_events(self, incident_uuid, limit: int = 50):
        def get_events_pack(payload: dict, limit: int = 50, offset: int = 0):
            """
            Получаю список событий
            :param payload: Параметры для выдачи (запрос на PDQL)
            :return:
            """
            try:
                res = self.print_response(
                    self.session.post(
                        f'{self.host}/api/events/v2/events/?incidentId={incident_uuid}&limit={limit}&offset={offset}',
                        json=payload),
                    expected_status=200)
            except Exception as err:
                logger.error(f"Не могу собрать данные. Какая-то редкая ошибка {err}")
                return False
            if res is False:
                return False
            return res.text

        query = {
            "filter": {
                "select": [
                    "_whitelisting",
                    "action",
                    "agent_id",
                    "aggregation_name",
                    "asset_ids",
                    "assigned_dst_host",
                    "assigned_dst_ip",
                    "assigned_dst_port",
                    "assigned_src_host",
                    "assigned_src_ip",
                    "assigned_src_port",
                    "body",
                    "category.generic",
                    "category.high",
                    "category.low",
                    "correlation_name",
                    "correlation_type",
                    "count",
                    "count.bytes",
                    "count.bytes_in",
                    "count.bytes_out",
                    "count.packets",
                    "count.packets_in",
                    "count.packets_out",
                    "count.subevents",
                    "datafield1",
                    "datafield10",
                    "datafield2",
                    "datafield3",
                    "datafield4",
                    "datafield5",
                    "datafield6",
                    "datafield7",
                    "datafield8",
                    "datafield9",
                    "detect",
                    "direction",
                    "dst.asset",
                    "dst.fqdn",
                    "dst.geo.asn",
                    "dst.geo.city",
                    "dst.geo.country",
                    "dst.geo.org",
                    "dst.host",
                    "dst.hostname",
                    "dst.ip",
                    "dst.mac",
                    "dst.port",
                    "duration",
                    "event_src.asset",
                    "event_src.category",
                    "event_src.fqdn",
                    "event_src.host",
                    "event_src.hostname",
                    "event_src.id",
                    "event_src.ip",
                    "event_src.subsys",
                    "event_src.title",
                    "event_src.vendor",
                    "event_type",
                    "generator",
                    "generator.type",
                    "generator.version",
                    "historical",
                    "id",
                    "importance",
                    "incorrect_time",
                    "input_id",
                    "interface",
                    "job_id",
                    "logon_type",
                    "mime",
                    "msgid",
                    "nas_ip",
                    "normalized",
                    "object",
                    "object.domain",
                    "object.group",
                    "object.hash",
                    "object.id",
                    "object.name",
                    "object.path",
                    "object.property",
                    "object.state",
                    "object.type",
                    "object.value",
                    "object.vendor",
                    "object.version",
                    "original_time",
                    "protocol",
                    "reason",
                    "recv_asset",
                    "recv_host",
                    "recv_ipv4",
                    "recv_ipv6",
                    "recv_time",
                    "remote",
                    "scope_id",
                    "siem_id",
                    "site_address",
                    "site_alias",
                    "site_id",
                    "site_name",
                    "src.asset",
                    "src.fqdn",
                    "src.geo.asn",
                    "src.geo.city",
                    "src.geo.country",
                    "src.geo.org",
                    "src.host",
                    "src.hostname",
                    "src.ip",
                    "src.mac",
                    "src.port",
                    "start_time",
                    "status",
                    "subevents",
                    "subject",
                    "subject.domain",
                    "subject.group",
                    "subject.id",
                    "subject.name",
                    "subject.privileges",
                    "subject.type",
                    "subject.version",
                    "tag",
                    "task_id",
                    "taxonomy_version",
                    "tcp_flag",
                    "tenant_id",
                    "text",
                    "time",
                    "type",
                    "uuid"
                ],
                "where": "",
                "orderBy": [
                    {
                        "field": "time",
                        "sortOrder": "descending"
                    }
                ],
                "groupBy": [],
                "aggregateBy": [],
                "distributeBy": [],
                "top": None,
                "aliases": {}
            },
            "groupValues": None,
            # "timeFrom": 1606809426,
            # "timeTo": 1606809426
        }
        all_inc_events = []
        logger.info(f"Получаю события по инциденту {incident_uuid}")
        res = get_events_pack(payload=query, limit=limit)
        if not res:
            logger.warning(f'При запросе событий по инциденту получили {res}')
            return all_inc_events
        total_count = json.loads(res).get('totalCount')
        if json.loads(res).get('message') == "Authorization has been denied for this request.":
            logger.error(json.loads(res))
            sys.exit(0)
        inc_events = json.loads(res).get('events')
        if not inc_events:
            return all_inc_events
        all_inc_events = all_inc_events + inc_events

        if total_count > limit:
            for jump in range(1, round(total_count / limit) + 1):
                logger.debug(f"    смещение {query['offset']} -> {jump * limit}")
                offset = jump * limit
                res = get_events_pack(query, limit=limit, offset=offset)
                inc_events = json.loads(res).get('events')
                if not isinstance(inc_events, list):
                    continue
                for incev in inc_events:
                    if incev not in all_inc_events:
                        all_inc_events.append(incev)

        logger.debug(f"  получено событий {len(all_inc_events)} из {total_count}")
        return all_inc_events

    def change_incident_status(self, incident, status=None):
        """
        Меняю статус инцидента
        :param incident:
        :param status:
        :return:
        """
        params = {"id": "InProgress", "measures": "Submitted to SIEM"}
        # params = {"id": "Closed", "measures": "Submitted to SIEM"}
        try:
            res = self.session.put(f"{self.host}/api/incidents/{incident['id']}/transitions", json=params)
            if res.status_code == 204:
                logger.info(f"Инцидент {incident['key']} закрыт [id: {incident['id']}]")
        except Exception as err:
            logger.error(f"Какая-то редкая ошибка {err}")

    def get_siem_version(self):
        res = self.print_response(
            self.session.get(f'{self.host}/api/deployment_configuration/v1/system_info'),
            expected_status=200,
            level="warning")
        if res is False:
            return {}
        return json.loads(res.text).get('productVersion')
