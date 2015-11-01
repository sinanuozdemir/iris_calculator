from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
visit = Table('visit', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('ip', String(length=64)),
    Column('lat', String(length=64)),
    Column('lng', String(length=64)),
    Column('city', String(length=64)),
    Column('country', String(length=64)),
    Column('browser', String(length=128)),
    Column('full_url', String(length=1024)),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['visit'].columns['browser'].create()
    post_meta.tables['visit'].columns['city'].create()
    post_meta.tables['visit'].columns['country'].create()
    post_meta.tables['visit'].columns['lat'].create()
    post_meta.tables['visit'].columns['lng'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['visit'].columns['browser'].drop()
    post_meta.tables['visit'].columns['city'].drop()
    post_meta.tables['visit'].columns['country'].drop()
    post_meta.tables['visit'].columns['lat'].drop()
    post_meta.tables['visit'].columns['lng'].drop()
