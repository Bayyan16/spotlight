# prompt_id=1712
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    self.forwardIndex[str(currentId)] = parsedText
    for position,term in enumerate(parsedText):
        stem = term.stem.encode("utf8")
        documents = self.invertedIndex[stem] if stem in self.invertedIndex else []
        documents.append((position,currentId)) 
        self.invertedIndex[stem] = documents

def startIndexer(self,indexDir):
    self.invertedIndex = shelve.open(os.path.join(indexDir,"invertedIndex"),'c')
    self.forwardIndex = shelve.open(os.path.join(indexDir,"forwardIndex"),'c')
    self.idToUrl = shelve.open(os.path.join(indexDir,"idToUrl"),'c')

def finishIndexer(self):
    self.invertedIndex.close()
    self.forwardIndex.close()
    self.idToUrl.close()

def loadIndexer(self,indexDir):
    self.invertedIndex = shelve.open(os.path.join(indexDir,"invertedIndex"),'r')
    self.forwardIndex = shelve.open(os.path.join(indexDir,"forwardIndex"),'r')
