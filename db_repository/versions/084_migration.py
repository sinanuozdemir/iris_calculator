from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
domain = Table('domain', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('text', String(length=256)),
    Column('catch_all', Boolean),
    Column('valid', Boolean, default=ColumnDefault(True)),
)

emailaddress = Table('emailaddress', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('address', String(length=256)),
    Column('status', String(length=64)),
    Column('domain_id', Integer, nullable=False),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['domain'].create()
    post_meta.tables['emailaddress'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['domain'].drop()
    post_meta.tables['emailaddress'].drop()
