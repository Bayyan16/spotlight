# prompt_id=1826
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    class Data:
        def __init__(self):
            training_file = 'data/train.p'
            validation_file= 'data/valid.p'
            testing_file = 'data/test.p'
    
            with open(training_file, mode='rb') as f:
                train = pickle.load(f)
            with open(validation_file, mode='rb') as f:
                valid = pickle.load(f)
            with open(testing_file, mode='rb') as f:
                test = pickle.load(f)
    
            self.X_train, self.y_train = train['features'], train['labels']
            self.X_valid, self.y_valid = valid['features'], valid['labels']
            self.X_test, self.y_test = test['features'], test['labels']
    
        def render_data(self):
            image_with_label = zip(self.X_train, self.y_train)
