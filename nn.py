import numpy as np
# This function learns parameters for the neural network and returns the model.
# - nn_hdim: Number of nodes in the hidden layer
# - num_passes: Number of passes through the training data for gradient descent
# - print_loss: If True, print the loss every 1000 iterations
class NN():
    def __init__(self, **kwargs):
        self.layers = kwargs.get('layers', None)
        self.print_loss = kwargs.get('print_loss', False)
        self.X = kwargs.get('X',None)
        self.y = kwargs.get('y',None)
        if self.X is None: raise Exception('no X found')
        if self.y is None: raise Exception('no y found')
        self.epsilon = kwargs.get('epsilon', .01) # learning rate for gradient descent
        self.reg_lambda = kwargs.get('reg_lambda', .01) # regularization strength
        self.model = {}
    def build_model(self, num_passes=1):
        if not self.layers: raise Exception('no layers found')

        num_examples = len(self.X)
        num_inputs = self.X.shape[1]
        self.layers.insert(0, num_inputs)
        num_classes = len(np.unique(self.y))
        self.layers.insert(len(self.layers), num_classes)
        W, B = [], []
        for i in range(len(self.layers)-1):
            W.append(np.random.randn(self.layers[i], self.layers[i+1]))
        for i in range(1,len(self.layers)):
            B.append(np.zeros((1,self.layers[i])))
            
        # Gradient descent. For each batch...
        for i in xrange(0, num_passes):
            if self.print_loss and i%1000==0:
                print "pass %d"%(i),
            A, z = [self.X], self.X
            # Forward propagation
            for i in range(len(W)):
                z = z.dot(W[i]) + B[i]
                if i < len(W)-1:
                    z = np.tanh(z)
                else:
                    z = np.exp(z)  
                    z = z / np.sum(z, axis=1, keepdims=True) # softmax
                A.append(z)
            # Backpropagation
            dW, dB = [], []
            delta = A.pop()
            delta[range(num_examples), self.y] -= 1
            while len(dW) < len(W):
                a = A.pop()
                dW.insert(0, self.reg_lambda * (a.T).dot(delta))
                dB.insert(0,np.sum(delta, axis=0, keepdims=True))
                w = W[len(W)-len(dW)]
                delta = delta.dot(w.T) * (1 - np.power(a, 2))

            # Gradient descent parameter update
            for w, dw in zip(W, dW): w += -self.epsilon * dw 
            for b, db in zip(B, dB): b += -self.epsilon * db
            # Assign new parameters to the model
            self.model = {'W': W, 'B': B} 
        return None
    def predict(self, x):
        z = x
        # Forward propagation
        for i in range(len(self.model['W'])):
            z = z.dot(self.model['W'][i]) + self.model['B'][i]
            if i < len(self.model['W'])-1:
                z = np.tanh(z)
            else:
                z = np.exp(z)  
                z = z / np.sum(z, axis=1, keepdims=True) # softmax
        exp_scores = np.exp(z)   # softmax
        probs = exp_scores / np.sum(exp_scores, axis=1, keepdims=True)
        return np.argmax(probs, axis=1)


# d = pd.read_csv('http://archive.ics.uci.edu/ml/machine-learning-databases/poker/poker-hand-testing.data')
# d.columns = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
# nn = NN(X = d[[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]].values, y = d[[11]].values, layers = [2])
# nn.build_model(num_passes=1)

# sum(nn.predict(d[[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]].values) == d[11]) / float(len(d[11]))

