import tensorflow as tf

 # Converting the model into Tensorflow serving
def Model_convertor(model_path, path): # sending model and the path to save
    
    model = tf.keras.models.load_model(model_path) # loading the model
    tf.saved_model.save(model, path) # saving the model as TensorFlow Serving


Model_convertor("./main_Models/Final-binary.h5", "./binary_classifier/binary_model/1")
