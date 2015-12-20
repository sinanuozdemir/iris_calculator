from controller import db
import models

def getModel(model, **kwargs):
	return db.session.query(model).filter_by(**kwargs).first()

def get_or_create(model, **kwargs):
	defaults = kwargs.get('defaults', {})
	if 'defaults' in kwargs:
		del kwargs['defaults']
	instance = db.session.query(model).filter_by(**kwargs).first()
	if instance:
		return instance, False
	else:
		kwargs.update(defaults)
		instance = model(**kwargs)
		db.session.add(instance)
		db.session.commit()
		db.session.close()
		return instance, True

