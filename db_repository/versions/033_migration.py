from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
app = Table('app', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('appid', String(length=64)),
    Column('website_id', Integer, nullable=False),
    Column('user_id', Integer, nullable=False),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['app'].columns['user_id'].create()
    post_meta.tables['app'].columns['website_id'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['app'].columns['user_id'].drop()
    post_meta.tables['app'].columns['website_id'].drop()
