from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
thread = Table('thread', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('threadid', String(length=64)),
    Column('origin', String(length=128)),
    Column('unique_thread_id', String(length=128)),
    Column('all_parties_replied', Boolean, default=ColumnDefault(False)),
    Column('people_in_conversation', Integer, default=ColumnDefault(0)),
    Column('last_checked', DateTime),
    Column('first_made', DateTime),
    Column('app_id', Integer),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['thread'].columns['threadid'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['thread'].columns['threadid'].drop()
