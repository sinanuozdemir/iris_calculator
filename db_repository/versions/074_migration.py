from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
thread = Table('thread', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('origin', String(length=128)),
    Column('unique_thread_id', String(length=128)),
    Column('last_checked', DateTime),
    Column('app_id', Integer),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['thread'].columns['app_id'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['thread'].columns['app_id'].drop()
