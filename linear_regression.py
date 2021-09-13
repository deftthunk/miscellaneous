from random import randint

TRAIN_SET_LIMIT = 500
TRAIN_SET_COUNT = 20
TRAIN_INPUT = list()
TRAIN_OUTPUT = list()

for i in range(TRAIN_SET_COUNT):
    a = randint(0, TRAIN_SET_LIMIT)
    b = randint(0, TRAIN_SET_LIMIT)
    c = randint(0, TRAIN_SET_LIMIT)
    d = randint(0, TRAIN_SET_LIMIT)
    e = randint(0, TRAIN_SET_LIMIT)
    op = a + (2*b) + (333*c) + (4*d) + (5*e)
    TRAIN_INPUT.append([a, b, c, d, e])
    TRAIN_OUTPUT.append(op)


from sklearn.linear_model import LinearRegression

predictor = LinearRegression(n_jobs=-1)
predictor.fit(X=TRAIN_INPUT, y=TRAIN_OUTPUT)

X_TEST = [[10, 20, 30, 40, 50]]
outcome = predictor.predict(X=X_TEST)
coefficients = predictor.coef_

print('Outcome : {}\nCoefficients : {}'.format(outcome, coefficients))
