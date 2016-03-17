from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
app = Table('app', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('appid', String(length=64)),
    Column('website_id', Integer, nullable=False),
    Column('google_email', String(length=128)),
    Column('google_access_token', Text),
    Column('google_refresh_token', Text),
    Column('user_id', Integer, nullable=False),
    Column('last_checked_inbox', DateTime),
    Column('next_check_inbox', DateTime),
    Column('frequency_of_check', Integer, default=ColumnDefault(20)),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['app'].columns['next_check_inbox'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['app'].columns['next_check_inbox'].drop()
