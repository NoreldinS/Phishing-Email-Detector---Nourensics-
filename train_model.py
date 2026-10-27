import pandas as pd #helps extract and organise data easily 
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB 
from sklearn.metrics import accuracy_score
import joblib



Bayes = MultinomialNB() #store our naive bayes classifier in Bayes
vectorizer = CountVectorizer() #creates the vectorizer object 
data = pd.read_csv("Phishing_Email.csv")  # Load the CSV dataset into a DataFrame where panda can access the data

data = data.dropna(subset=["Email Text"]) #remove all empty email text rows
x = data["Email Text"]
y = data["Email Type"]

x_train, x_test, y_train, y_test = train_test_split( #Using the function train_test_split we split the 2 data sets, 20% testing and 80% training data 
    x, y, test_size=0.2, random_state=42, stratify=y #random state ensures that every time we train or test the data its beeing tested on a different set of data
)

x_count = vectorizer.fit_transform(x_train) # transform text into numbers, fit identifies different words and learns them, we tranform every text into a row of numbers hwoing how many each word appears
test_count = vectorizer.transform(x_test) #trasnforms the testing data texts into numbers too to compare to the training data 

Bayes.fit(x_count, y_train) 

y_pred = Bayes.predict(test_count) #using our testing emails, quick test using the data leanred from the training data
results = accuracy_score(y_test, y_pred) #storing how accurate the predictions are to the true types of the emails

print("Model accuracy:", results * 100, "%")

joblib.dump(Bayes, "naive_bayes_model.pkl") #saves our training model 
joblib.dump(vectorizer, "vectorizer.pkl") #Saves the CountVectorizer, including the vocabulary it learned.


