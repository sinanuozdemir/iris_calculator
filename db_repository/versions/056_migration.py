from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
email = Table('email', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('emailid', String(length=64)),
    Column('text', Text),
    Column('html', Text),
    Column('to_address', Text),
    Column('from_address', Text),
    Column('cc_address', Text),
    Column('bcc_address', Text),
    Column('app_id', Integer),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['email'].columns['bcc_address'].create()
    post_meta.tables['email'].columns['cc_address'].create()
    post_meta.tables['email'].columns['from_address'].create()
    post_meta.tables['email'].columns['html'].create()
    post_meta.tables['email'].columns['to_address'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['email'].columns['bcc_address'].drop()
    post_meta.tables['email'].columns['cc_address'].drop()
    post_meta.tables['email'].columns['from_address'].drop()
    post_meta.tables['email'].columns['html'].drop()
    post_meta.tables['email'].columns['to_address'].drop()
