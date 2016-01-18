import os
import urllib
basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = 'postgres://sinanuozdemir:tier5beta@web-analytics2.c7o6nxvtuh6x.us-west-2.rds.amazonaws.com:5432/web_analytics'
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')



CELERY_IGNORE_RESULT = True
CELERY_TASK_SERIALIZER='json'
CELERY_ACCEPT_CONTENT = ['json', 'msgpack', 'yaml']
CELERY_RESULT_SERIALIZER='json'
CELERY_RESULT_BACKEND = 'amqp'
BROKER_CONNECTION_TIMEOUT = 30
BROKER_POOL_LIMIT = 1 # Will decrease connection usage
# CELERY_TIMEZONE='US/Eastern'
CELERY_ENABLE_UTC=True
BROKER_TRANSPORT = 'sqs'
BROKER_TRANSPORT_OPTIONS = {
    'region': 'us-west-2',
}
CELERY_IMPORTS=("controller", "modles",)
CELERY_SEND_EVENTS = False
CELERY_EVENT_QUEUE_EXPIRE = 60
CELERY_EVENT_QUEUE_TTL = 10
CELERY_ACKS_LATE = True
CELERYD_PREFETCH_MULTIPLIER = 1
CELERY_DEFAULT_QUEUE = 'latracking'
CELERY_BROKER_URL = urllib.quote('sqs://AKIAIKM6CUVGB6BQ34CA:ZxrtSwEcVlBJd/cyTvl5GysShVKCclJJEZyoVoBO@')


