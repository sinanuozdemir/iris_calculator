from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
visit = Table('visit', pre_meta,
    Column('id', INTEGER, primary_key=True, nullable=False),
    Column('full_url', VARCHAR(length=1024)),
    Column('city', VARCHAR(length=64)),
    Column('country', VARCHAR(length=64)),
    Column('lat', VARCHAR(length=64)),
    Column('lng', VARCHAR(length=64)),
    Column('date', TIMESTAMP),
    Column('private_ip', VARCHAR(length=64)),
    Column('public_ip', VARCHAR(length=64)),
    Column('browser', VARCHAR(length=1024)),
    Column('is_mobile', BOOLEAN),
    Column('is_pc', BOOLEAN),
    Column('is_tablet', BOOLEAN),
    Column('user_agent', VARCHAR(length=1024)),
    Column('is_bot', BOOLEAN),
    Column('secure', BOOLEAN),
    Column('state', VARCHAR(length=64)),
    Column('after', VARCHAR(length=1024)),
    Column('base', VARCHAR(length=1024)),
    Column('gets', VARCHAR(length=1024)),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    pre_meta.tables['visit'].columns['base'].drop()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    pre_meta.tables['visit'].columns['base'].create()
