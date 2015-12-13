from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
link = Table('link', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('linkid', String(length=64)),
    Column('url', String(length=1024)),
    Column('text', String(length=1024)),
    Column('app_id', Integer),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['link'].columns['text'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['link'].columns['text'].drop()
