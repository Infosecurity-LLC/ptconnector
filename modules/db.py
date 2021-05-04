import pymongo
from pymongo import errors
import logging
from datetime import datetime, timedelta
from bson import ObjectId

logger = logging.getLogger('pt_connector.db')


class Mongo:
    def __init__(self, mongo_setting):
        self.__setting = mongo_setting
        self.__mongo = self.__init_mongo(self.__setting)

    @staticmethod
    def __init_mongo(mongo_setting):
        if mongo_setting.get('user'):
            return pymongo.MongoClient(
                host=mongo_setting['host'],
                port=mongo_setting['port'],
                username=mongo_setting['user'],
                password=mongo_setting['password'],
                authSource=mongo_setting['dbname'],
                authMechanism='SCRAM-SHA-1'
            )
        return pymongo.MongoClient(
            host=mongo_setting['host'],
            port=mongo_setting['port']
        )

    def create_index(self, fields, collection, unique=True):
        _collection = self.__mongo[self.__setting['dbname']][collection]
        index_fields = []
        if isinstance(fields, list):
            for field in fields:
                index_fields.append((field, pymongo.ASCENDING))
        if isinstance(fields, str):
            index_fields.append((fields, pymongo.ASCENDING))
        try:
            _collection.create_index(index_fields, unique=unique)
        except Exception as err:
            logger.critical('Не удалось создать индекс. Error {}'.format(err))

    @staticmethod
    def convert_object_id(document, keys=None):
        """
        Сконвертировать ObjectID из документа Mongo в str
        :param document: документ
        :param keys: список ключей, который необходимо вернуть. Если не указано, то вернуть все ключи
        :return: словарь
        """
        if not document:
            return None
        if not keys:
            keys = document.keys()
        return {k: document[k] if not isinstance(document[k], ObjectId) else str(document[k]) for k in keys}

    def insert_document(self, data, collection):
        """Записываем в базу новый документ, возвращаем id string"""
        _collection = self.__mongo[self.__setting['dbname']][collection]
        try:
            _id = _collection.insert_one(data).inserted_id
        except pymongo.errors.DuplicateKeyError:
            logger.warning('Запись уже существует {}'.format(data))
            return False
        _id = str(_id)
        return _id

    def insert_documents(self, data, collection):
        """Записываем в базу новый документ, возвращаем id string"""
        _collection = self.__mongo[self.__setting['dbname']][collection]
        _ids = _collection.insert_many(data).inserted_ids
        # _id = str(_id)
        return _ids

    def get_last_position(self, dbname, fsf):
        """ Получаем дату, с которой нужно собрать новые сработки """

        def new_lp():
            t_now = datetime.utcnow()
            data = dict(
                _status=0,
                last_position_time=t_now.isoformat(),
                last_position_utime=int(t_now.timestamp())
            )
            return t_now, self.__mongo[dbname]['work_time'].insert_one(data).inserted_id

        new_last_start_time, new_lp_id = new_lp()
        try:
            res = self.__mongo[dbname]['work_time'].find({"_status": 1}).sort('_id', -1).limit(1)[:1][
                0]
        except IndexError:
            logger.warning(f"Не найдено время последнего запуска. Зададим по дефолту "
                           f"-{fsf} min")
            nlst = new_last_start_time - timedelta(minutes=fsf)
            return int(nlst.timestamp()), new_lp_id
        last_start_time = int(res.get('last_position_utime'))
        return last_start_time, new_lp_id

    def update_last_end_time(self, new_lp_id):
        """
        Если сбор данных  прошёл успено,
        то разрешаем новый last_position к использованию при следующем включении
        :param new_lp_id: id нового LP, который нужно пометить как подтверждённый
        :return:
        """
        t_now = datetime.utcnow()
        data = dict(
            _status=1,
            end_work_time=t_now.isoformat()
        )
        return self.__mongo[self.__setting['dbname']]['work_time'].update_one({'_id': new_lp_id}, {"$set": data})

    def get_query_filter(self, filter_, collection, show=None, skip=None, limit=None, count=None):
        """
        Возвращает список записей отфильтрованных по словарю filter_. Отображает только данные по ключам из списка show.
        Если список show пустой, возвращает весь результат.
        ObjectID конвертирует в строку.
        :param filter_:
        :param show:
        :param collection:
        :param skip:
        :param limit:
        :param count:
        :return:
        """

        def collect(jobs, show_filter=None):
            """Конвертировать ObjectID в строку и вернуть только ключи согласно списку фильтрации"""
            if not jobs:
                return False
            resp = []
            for job in jobs:
                resp.append(self.convert_object_id(job, show_filter))
            return resp

        _collection = self.__mongo[self.__setting['dbname']][collection]
        _ids = []
        if not filter_ or not isinstance(filter_, dict):
            return False
        if not skip and not limit:
            _ids = _collection.find(filter_)
        if not skip and not limit and count:
            return _collection.find(filter_).count()
        if skip:
            _ids = _collection.find(filter_).skip(skip)
        if limit:
            _ids = _collection.find(filter_).limit(limit)
        if skip and limit:
            _ids = _collection.find(filter_).skip(skip).limit(limit)

        response = collect(jobs=_ids, show_filter=show)
        return response

    def update_document(self, filter_, values_dict, collection):
        """Обновить документ. Если фильтр содержит _id, то конвертируем в ObjectId и фильтруем по нему"""
        filter_ = {'_id': ObjectId(filter_["_id"])} if filter_.get("_id") else filter_
        # logger.debug(f'filter: {filter_}, {collection}')
        _collection = self.__mongo[self.__setting['dbname']][collection]
        res = _collection.update_one(filter_, values_dict)
        return res.matched_count

    def update_documents(self, filter_, values_dict, collection):
        if "_id" in filter_ and filter_['_id'].get("$in"):
            idlist = []
            for _id in filter_["_id"]["$in"]:
                idlist.append(ObjectId(_id))
            filter_["_id"]["$in"] = idlist

        _collection = self.__mongo[self.__setting['dbname']][collection]
        res = _collection.update_many(filter_, values_dict)
        return res.matched_count
