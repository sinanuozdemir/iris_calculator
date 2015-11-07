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
    post_meta.tables['user'].columns['is_active'].create()
    post_meta.tables['user'].columns['is_anonymous'].create()
    post_meta.tables['user'].columns['is_authenticated'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['user'].columns['is_active'].drop()
    post_meta.tables['user'].columns['is_anonymous'].drop()
    post_meta.tables['user'].columns['is_authenticated'].drop()
