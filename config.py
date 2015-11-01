import os
basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = 'postgres://sinanuozdemir:tier5beta@web-analytics2.c7o6nxvtuh6x.us-west-2.rds.amazonaws.com:5432/web_analytics'
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')
