try:
	import numpy as np
except: 
	pass

import json
import re
from collections import Counter
import string
from itertools import groupby, izip, permutations
from controller import db
import models
import nn

class TextPredictor():
	def __init__(self):
		self.computed ={'bayes':False, 'neural':False}
	def _computePrelimsForBayes(self):
		self.texts, self.labels= [], []
		self.label_counts = {}
		self.word_counts = {}
		self.total_counts = {}
		for text_obj in db.session.query(models.TextForML).all():
			text = text_obj.raw_text
			label = text_obj.text_class
			if not (text and label): continue
			if label != label.upper():
				text = text.replace('\r','')
				text = text.replace('\n',' ')
				if text not in self.texts: 
					self.texts.append(text)
					self.labels.append(label)
					self.label_counts[label] = self.label_counts.get(label,0)+1
					attr = self.getTextAttributes(text)
					if not attr: continue
					if label not in self.word_counts: self.word_counts[label] = {}
					for word in attr['word_counts'].keys():
						self.word_counts[label][word] = self.word_counts[label].get(word,0)+1
						self.total_counts[word] = self.total_counts.get(word,0)+1
					for word in attr['word_pair_counts'].keys():
						self.word_counts[label][word] = self.word_counts[label].get(word,0)+1
						self.total_counts[word] = self.total_counts.get(word,0)+1

		self.total_count = float(sum(self.label_counts.values()))
		self.computed['bayes'] = True
	def _getSentenceAttributes(self, sentence):
		# change all multiple white spaces to a single space
		sentence = sentence.strip()
		sentence = re.sub(r'\s+', ' ', sentence)
		if len(sentence) <= 1: return None

		# preliminary cleaning
		attr = {'text':sentence}
		attr['question'] = sentence[-1] == '?'
		attr['word_count'] = sentence.count(' ') + 1


		#strip punctuations away
		exclude = set(string.punctuation)
		wo_punc = ''.join(ch.lower() for ch in sentence if ch not in exclude)

		attr['sentence_wo_punc'] = wo_punc
		attr['character_count'] = len(wo_punc) - attr['word_count'] + 1 #without spaces
		attr['average_character_per_word'] = attr['character_count'] / float(attr['word_count'])
		attr['words_tokenized'] = wo_punc.split(' ')
		attr['word_counts'] = dict(Counter(attr['words_tokenized']))
		attr['word_pairs'] = [' '.join(pair) for pair in izip(attr['words_tokenized'][:-1], attr['words_tokenized'][1:])]
		attr['word_pair_counts'] = dict(Counter(attr['word_pairs']))
		return attr
	def getTextAttributes(self, text):
		s_attr = {'sentences':[], 'total_text':text}
		sentence_re = '(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|\,)\s'
		for sentence in re.split(sentence_re, text):
			attr = self._getSentenceAttributes(sentence)
			if attr: 
				s_attr['sentence_count'] = s_attr.get('sentence_count', 0) + 1
				s_attr['sentences'].append(attr)
		sentence_attr = self._getSentenceAttributes(text)
		if sentence_attr: 
			s_attr.update(sentence_attr)
		else:
			return None
		return s_attr
	def getPredictionsSingleWord(self, word):
		word = word.strip().lower()
		exclude = set(string.punctuation)
		word = ''.join(ch.lower() for ch in word if ch not in exclude)
		# change all multiple white spaces to a single space
		word = re.sub(r'\s+', ' ', word)
		# return [(k, v.get(word, .01)/float(label_counts[k])) for k, v in word_counts.iteritems() if word in v]
		return sorted([(k, v.get(word, .001)/float(self.label_counts[k]) / (self.total_counts.get(word, self.total_count*.7)/self.total_count) * (self.label_counts[k] / float(self.total_count))) for k, v in self.word_counts.iteritems()], key = lambda x:-x[1])
	def predictSentenceBayes(self, sentence):
		attr = self.getTextAttributes(sentence)
		tot = []
		for word in attr['words_tokenized']+attr['word_pairs']:
			tot += self.getPredictionsSingleWord(word)
		tot = sorted(tot)
		predict_proba = {}
		for k, v in groupby(tot, lambda x:x[0]):
			predict_proba[k] = reduce(lambda x,y:x*y, [a[1] for a in v])
		top_ones = sorted(predict_proba.iteritems(), key = lambda x:-x[1])
		sum_values = sum([t[1] for t in top_ones])
		top_ones = [(k, v/sum_values) for k, v in top_ones]
		return {'sentence':sentence, 'top_choices':top_ones, 'choice':max(top_ones, key = lambda x:x[1])}
	def predictTextBayes(self, text):
		result = {'text':text, 'sentences':[]}
		attr = self.getTextAttributes(text)
		for sentence in attr['sentences']:
			result['sentences'].append({'text':sentence['text'], 'prediction':self.predictSentenceBayes(sentence['text'])})
		return result
	def _computePrelimsForNN(self, how_many = 10):
		self.how_many = how_many
		self.A = None
		self.labels_nn = ['test']
		training_set = db.session.query(models.TextForML).all()
		for text_obj in training_set:
			text = text_obj.raw_text
			label = text_obj.text_class
			if not (text and label): continue
			newrow = np.array([a[1] for a in sorted(self._getAlphaCounts(text).iteritems())])
			if self.A is None: self.A = np.array([0]*len(newrow))
			for i in range(10):	
				self.labels_nn.append(label)
				self.A = np.vstack([self.A, newrow])

		self.label_ids_nn = {l:i for i, l in enumerate(set(self.labels_nn))}
		converted_labels = [self.label_ids_nn[l] for l in self.labels_nn]
		self.converted_labels_back = {v:k for k, v in self.label_ids_nn.iteritems()}
		self.neural_nets = []
		for i in range(how_many):
			neural_net = nn.NN(X = self.A, y = np.array(converted_labels), layers = [30]*2, print_loss=False)
			neural_net.build_model(num_passes=100)
			self.neural_nets.append(neural_net)
			print "done training model %d / %d"%(i+1, how_many)
		self.computed['neural'] = True
	def predictSentenceNN(self, text):
		text_as_row = [a[1] for a in sorted(self._getAlphaCounts(text).items())]
		choices = [self.converted_labels_back[i.predict(np.array(text_as_row))[0]] for i in self.neural_nets]
		top_choices = Counter(choices).most_common()
		top_choices = [[k, v/float(self.how_many)] for k, v in top_choices]
		return {'choice':sorted(top_choices, key = lambda x:-x[1])[0], 'top_choices':top_choices}
	def predictTextNN(self, text):
		result = {'text':text, 'sentences':[]}
		attr = self.getTextAttributes(text)
		for sentence in attr['sentences']:
			result['sentences'].append({
					'text':sentence['text'], 
					'prediction':self.predictSentenceNN(sentence['text'])
				})
		return result
	def _getAlphaCounts(self, text, num = 2):
		text = text.lower()
		alphabet = 'abcdefghijklmnopqrstuvwxyz '+string.punctuation
		return {k:text.count(k) for k in alphabet}
	def predictSentence(self, sentence, how = 'bayes'):
		if 'neural' in how: return self.predictSentenceNN(sentence)
		elif 'bayes' in how: return self.predictSentenceBayes(sentence)
		return None
	def compute(self, which = None):
		if which == 'bayes': self._computePrelimsForBayes()
		elif which == 'neural': self._computePrelimsForNN()
		return None
	def predict(self, text, how = 'all'):
		result = {}
		if how == 'all': how = 'bayes,neural'
		result = {'text':text, 'sentences':[]}
		attr = self.getTextAttributes(text)
		for sentence in attr['sentences']:
			sentence_done = {
					'text':sentence['text'], 
					'predictions':{}
				}
			for h in how.split(','):
				h = h.strip().lower()
				if not self.computed[h]: self.compute(h)
				try:
					sentence_done['predictions'][h] = self.predictSentence(sentence['text'], how = h)
				except Exception as e: 
					pass
			overall = {}
			overalls = reduce(lambda x,y: x+y, [v['top_choices'] for v in sentence_done['predictions'].values()])
			overalls = sorted(overalls, key = lambda x:x[0])
			for k, v in groupby(overalls, key = lambda x:x[0]):
				v = [a[1] for a in v]
				overall[k] = sum(v)/len(sentence_done['predictions'])
			sentence_done['overall_prediction'] = max(overall.items(), key = lambda x:x[1])
			result['sentences'].append(sentence_done)
		result['prediction_by_sentence'] = [(s['text'], s['overall_prediction'][0]) for s in result['sentences']]
		return result











