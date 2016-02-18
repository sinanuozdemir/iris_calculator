import random
import math
import itertools
import re
from collections import Counter, defaultdict
import string

known = ['job_title', 'person_location', 'technologies', 'company_industry', 'person__industry', 'company_location']

ENGLISH_STOP_WORDS = [
    "a", "about", "above", "across", "after", "afterwards", "again", "against",
    "all", "almost", "alone", "along", "already", "also", "although", "always",
    "am", "among", "amongst", "amoungst", "amount", "an", "and", "another",
    "any", "anyhow", "anyone", "anything", "anyway", "anywhere", "are",
    "around", "as", "at", "back", "be", "became", "because", "become",
    "becomes", "becoming", "been", "before", "beforehand", "behind", "being",
    "below", "beside", "besides", "between", "beyond", "bill", "both",
    "bottom", "but", "by", "call", "can", "cannot", "cant", "co", "con",
    "could", "couldnt", "cry", "de", "describe", "detail", "do", "done",
    "down", "due", "during", "each", "eg", "eight", "either", "eleven", "else",
    "elsewhere", "empty", "enough", "etc", "even", "ever", "every", "everyone",
    "everything", "everywhere", "except", "few", "fifteen", "fify", "fill",
    "find", "fire", "first", "five", "for", "former", "formerly", "forty",
    "found", "four", "from", "front", "full", "further", "get", "give", "go",
    "had", "has", "hasnt", "have", "he", "hence", "her", "here", "hereafter",
    "hereby", "herein", "hereupon", "hers", "herself", "him", "himself", "his",
    "how", "however", "hundred", "i", "ie", "if", "in", "inc", "indeed",
    "interest", "into", "is", "it", "its", "itself", "keep", "last", "latter",
    "latterly", "least", "less", "ltd", "made", "many", "may", "me",
    "meanwhile", "might", "mill", "mine", "more", "moreover", "most", "mostly",
    "move", "much", "must", "my", "myself", "name", "namely", "neither",
    "never", "nevertheless", "next", "nine", "no", "nobody", "none", "noone",
    "nor", "not", "nothing", "now", "nowhere", "of", "off", "often", "on",
    "once", "one", "only", "onto", "or", "other", "others", "otherwise", "our",
    "ours", "ourselves", "out", "over", "own", "part", "per", "perhaps",
    "please", "put", "rather", "re", "same", "see", "seem", "seemed",
    "seeming", "seems", "serious", "several", "she", "should", "show", "side",
    "since", "sincere", "six", "sixty", "so", "some", "somehow", "someone",
    "something", "sometime", "sometimes", "somewhere", "still", "such",
    "system", "take", "ten", "than", "that", "the", "their", "them",
    "themselves", "then", "thence", "there", "thereafter", "thereby",
    "therefore", "therein", "thereupon", "these", "they", "thick", "thin",
    "third", "this", "those", "though", "three", "through", "throughout",
    "thru", "thus", "to", "together", "too", "top", "toward", "towards",
    "twelve", "twenty", "two", "un", "under", "until", "up", "upon", "us",
    "very", "via", "was", "we", "well", "were", "what", "whatever", "when",
    "whence", "whenever", "where", "whereafter", "whereas", "whereby",
    "wherein", "whereupon", "wherever", "whether", "which", "while", "whither",
    "who", "whoever", "whole", "whom", "whose", "why", "will", "with",
    "within", "without", "would", "yet", "you", "your", "yours", "yourself",
    "yourselves"]
    

exclude = set(string.punctuation)

class MyCountVectorizer():
    def __init__(self, ngram_range=(1,1), stop_words = 'english'):
        self.ngram_range = ngram_range
        self.all_words = []
        self.stop_words = None
        if stop_words == 'english':
            self.stop_words = ENGLISH_STOP_WORDS
    def tokenize(self, s):
        s = re.sub('[\-\|\/]', ' ', s)
        s = ''.join(ch.lower() for ch in s if ch not in exclude)
        first = re.split('\s+', s.strip())
        if self.stop_words:
            first = [f for f in first if f not in self.stop_words]
        output = []
        for n in range(self.ngram_range[0], self.ngram_range[1]+1):
            for i in range(len(first)-n+1):
                output.append(first[i:i+n])
        return [' '.join(x).strip() for x in output]
    def fit_transform(self, texts):
        tokenized = map(self.tokenize, texts)
        self.all_words = list(set(reduce(lambda x, y:x+y, tokenized)))
        return map(lambda b: [b.lower().count(s) for s in self.all_words], texts)
    def get_feature_names(self):
        return self.all_words


class MyTextClassifier():
    def __init__(self, ngram_range = (1,1)):
        self.ngram_range = ngram_range
    def fit(self, X, y):
        self.num_docs = len(X)
        self.word_counts = {}
        self.priors = {k:float(v)/self.num_docs for k, v in Counter(y).iteritems()}
        self.labels = self.priors.keys()
        
        self.counts = {l:0 for l in self.labels}
        c = MyCountVectorizer(ngram_range = self.ngram_range)
        for text, label in zip(X, y):
            for word, count in Counter(c.tokenize(text)).iteritems():
                self.counts[label]+=count
                if word not in self.word_counts: self.word_counts[word] = {l:0 for l in self.labels}
                self.word_counts[word][label] += count
        self.vocab = self.word_counts.keys()
        self.indicators = {}
    def predict_proba(self, a):
        prob = {}
        c = MyCountVectorizer(ngram_range=self.ngram_range)
        for label in self.priors:
            p_label = self.priors[label]
            p_words = 1.
            log_p_words = 0.
            # print c.tokenize(a)
            for tokenized in c.tokenize(a):  
                p_word_given_label = float(self.word_counts.get(tokenized, {}).get(label, 0))
                p_word_given_label /= self.counts[label]
                if p_word_given_label == 0: p_word_given_label = 1. / sum(self.counts.values())
                # print label, tokenized, p_word_given_label
                if p_word_given_label:
                    log_p_words += math.log(p_word_given_label)
            # print label, log_p_words, math.exp(log_p_words), p_label
            prob[label] = math.exp(log_p_words)# * p_label
        if sum(prob.values()) > 0:
            prob = {k:v/sum(prob.values()) for k, v in prob.iteritems()}
            prob = {k:round(v/sum(prob.values()), 2) for k, v in prob.iteritems()}
        return prob
        
    def predict(self, value):
        try:
            p = self.predict_proba(value)
            if sum(p.values()) > 0:
                return max(p, key=p.get) 
            else:
                return 'NO TAG'
        except:
            return self.predict_values(value)
    def predict_values(self, values):
        return map(self.predict, values)
    def analyze(self):
        an = {}
        all_words = set()
        for label in self.labels:
            words = []
            probs = []
            for tokenized in self.vocab:
                p_word_given_label = float(self.word_counts.get(tokenized, {}).get(label, 0))
                p_word_given_label /= len(self.vocab)+ self.counts[label]
                words.append( [tokenized, p_word_given_label] )
                probs.append(p_word_given_label)
            avg = sum(probs) / len(probs)
            all_words |= set([w[0] for w in words])
            for w in words: w[1] = round(w[1] / avg, 3)
            new_words = {}
            words = dict(sorted(words, key = lambda x:x[1]))
            for k, v in words.iteritems():
                if v == 0:
                    continue
                good = True
                for k1, v2 in words.iteritems():
                    if k1 == k: continue
                    if v == v2 and k in k1: 
                        good = False
                if good: new_words[k] = v
            an[label] = new_words
        
        new = {k:[] for k in an.keys()}
        for word in set(reduce(lambda x, y:x+y, [v.keys() for v in an.values()])):
            belongs_to = max(an, key=lambda x:an[x].get(word, 0))
            score = 0
            for k, v in an.iteritems():
                if k == belongs_to:
                    score += v.get(word, 0)
                else:
                    score -= v.get(word, 0)
            new[belongs_to].append((word, round(score, 2)))
        new = {k:sorted(v, key=lambda x:-x[1])[:5] for k, v in new.iteritems()}
        self.indicators = new
        return new

