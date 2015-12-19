from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
user = Table('user', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('apps_allowed', Integer, default=ColumnDefault(0)),
    Column('nickname', String(length=64)),
    Column('first_name', String(length=64)),
    Column('google_email', String(length=128)),
    Column('google_access_token', Text),
    Column('google_refresh_token', Text),
    Column('login_check', String(length=64)),
    Column('is_verified', Boolean),
    Column('pw_hash', String(length=512)),
    Column('email', String(length=120)),
    Column('is_authenticated', Boolean),
    Column('is_active', Boolean),
    Column('is_anonymous', Boolean),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['user'].columns['google_access_token'].create()
    post_meta.tables['user'].columns['google_email'].create()
    post_meta.tables['user'].columns['google_refresh_token'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['user'].columns['google_access_token'].drop()
    post_meta.tables['user'].columns['google_email'].drop()
    post_meta.tables['user'].columns['google_refresh_token'].drop()
