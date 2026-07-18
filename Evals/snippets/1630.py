# prompt_id=1630
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    # Learning setup
    t_params = config.training_params
    sgd = SGD(lr=t_params["learning_rate"], decay=t_params["decay"],
              momentum=t_params["momentum"], nesterov=t_params["nesterov"])
    adam = Adam(lr=0.001, beta_1=0.9, beta_2=0.999, epsilon=1e-08)
    optimizer = eval(t_params['optimizer'])
    metrics = ['mean_squared_error']
    if config.model_arch["final_activation"] == 'softmax':
        metrics.append('categorical_accuracy')
    if t_params['loss_func'] == 'cosine':
        loss_func = eval(t_params['loss_func'])
    else:
        loss_func = t_params['loss_func']
    model.compile(loss=loss_func, optimizer=optimizer,metrics=metrics)

    return model

def load_data_preprocesed(params, X_path, Y_path, dataset, val_percent, test_percent, n_samples, with_metadata=False, only_metadata=False, metadata_source='rovi'):
    factors = np.load(common.DATASETS_DIR+'/y_train_'+Y_path+'.npy') # OJO remove S
    index_factors = open(common.DATASETS_DIR+'/items_index_train_'+dataset+'.tsv').read().splitlines()
