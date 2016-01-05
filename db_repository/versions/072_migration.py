from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
email = Table('email', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('emailid', String(length=64)),
    Column('google_message_id', String(length=128)),
    Column('google_thread_id', String(length=128)),
    Column('textblob_sentiment', Float),
    Column('makeshift_sentiment', Float),
    Column('text', Text),
    Column('html', Text),
    Column('to_address', Text),
    Column('bounce', Boolean, default=ColumnDefault(False)),
    Column('bounced_email', String(length=256)),
    Column('from_address', Text),
    Column('cc_address', Text),
    Column('bcc_address', Text),
    Column('subject', Text),
    Column('date_sent', DateTime),
    Column('app_id', Integer),
    Column('thread_id', Integer),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['email'].columns['makeshift_sentiment'].create()
    post_meta.tables['email'].columns['textblob_sentiment'].create()
    post_meta.tables['email'].columns['thread_id'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['email'].columns['makeshift_sentiment'].drop()
    post_meta.tables['email'].columns['textblob_sentiment'].drop()
    post_meta.tables['email'].columns['thread_id'].drop()
