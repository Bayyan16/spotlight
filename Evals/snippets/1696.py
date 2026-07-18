# prompt_id=1696
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    #
    dma_seq = DMASequencer(version = i,
                           ruby_system = ruby_system)
    
    dma_cntrl = DMA_Controller(version = i,
                               dma_sequencer = dma_seq,
                               transitions_per_cycle = options.ports,
                               ruby_system = ruby_system)
    
    exec("ruby_system.dma_cntrl%d = dma_cntrl" % i)
    exec("ruby_system.dma_cntrl%d.dma_sequencer.slave = dma_port" % i)
    dma_cntrl_nodes.append(dma_cntrl)
    
    # Connect the directory controllers and the network
    dma_cntrl.mandatoryQueue = MessageBuffer()
    dma_cntrl.requestToDir = MessageBuffer()
    dma_cntrl.requestToDir.master = ruby_system.network.slave
    dma_cntrl.responseFromDir = MessageBuffer(ordered = True)
    dma_cntrl.responseFromDir.slave = ruby_system.network.master
