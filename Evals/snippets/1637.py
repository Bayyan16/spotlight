# prompt_id=1637
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    from PIL import Image
    import numpy as np
    from utils import Vocabulary
    
    class CocoDataset(data.Dataset):
    
        def __init__(self, root, anns, vocab, mode='train',transform=None):
    
            self.root = root
            self.anns = json.load(open(anns))
            self.vocab = pickle.load(open(vocab, 'rb'))
            self.transform = transform
    
            self.data = [ann for ann in self.anns if ann['split'] == mode]
    
    
        def __getitem__(self, index):
            data  = self.data
            vocab = self.vocab
            # load image
