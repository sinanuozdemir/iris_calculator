from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
mlmodel = Table('mlmodel', pre_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('model', LargeBinary),
    Column('ml_model', LargeBinary),
)

mlmodel = Table('mlmodel', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('json_model', PickleType(pickler='json')),
    Column('ml_model', PickleType(pickler='cPickle.pickle')),
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    pre_meta.tables['mlmodel'].columns['model'].drop()
    post_meta.tables['mlmodel'].columns['json_model'].create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    pre_meta.tables['mlmodel'].columns['model'].create()
    post_meta.tables['mlmodel'].columns['json_model'].drop()
