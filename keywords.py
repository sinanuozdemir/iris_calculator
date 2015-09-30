from sklearn.feature_extraction.text import TfidfVectorizer

def getKeyWords(texts):
	vect = TfidfVectorizer(ngram_range=(1,2), stop_words='english')
	matrix = vect.fit_transform(texts)
	freqs = [(word, matrix.getcol(idx).sum()) for word, idx in vect.vocabulary_.items()]
	#sort from largest to smallest
	important_phrases = []
	bad = ['look', 'looking', 'join', 'recently', 'seeking']
	for phrase, times in sorted (freqs, key = lambda x: -x[1])[:20]:
		# print phrase, times
		if phrase not in bad:
			important_phrases.append(phrase)
	return important_phrases