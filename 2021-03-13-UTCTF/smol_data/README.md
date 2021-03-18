# Smol data (forensics, 994p, 26 solved)

## Description

```
It seems some squares have snuck into NLSS, the lines conference. Can you review this attendance data to find the impostors before all the lines are squared?

Once you find the records that do not belong to a line, combine their labels based on the order in which they appear in the file to get the flag.
```

We get [CSV data](anomaly_detect.zip)

## Task analysis

The idea behind the task seems quite clear.
We have a CSV dataset with lots of data columns, one `out` column and one column with a single letter in each row.
The task suggests that we need to find outliers in the dataset and combine associated letters to get the flag.
It's also strongly suggested we need to finde a `line`

## Solution

Following the suggestion we try to make linear regression from the data, and use it to predict values for each row, and compare this to `out`.
It turns out most records have very small error, but there are a bunch with significantly higher errors.
We filter those and combine into a flag.

### Regression

First calculate regression over the data

```python
from pandas import read_csv
from sklearn.linear_model import LinearRegression

url = 'test.csv'
df = read_csv(url, header=None)
data = df.values[1:]
results = {x[-2]: x[-1] for x in data}
position = {x[-2]: i for i, x in enumerate(data)} # result_value -> initial position in data
X, y = data[:, :-2], data[:, -2]
model = LinearRegression()
model.fit(X, y)
yhat = model.predict(X)
```

### Find outliers

Calculate difference between predicted value and given output

```python
diffs = []
d = {}
for i in range(len(yhat)):
    dif = abs(yhat[i] - float(y[i]))
    d[dif] = y[i]
    diffs.append(dif)
diffs = sorted(diffs, reverse=True)
```

### Combine flag

Use the mapping between value and position to combine the flag:

```python
final = {}
for dif in diffs:
    if dif > 30: # empirically
        y = d[dif]
        final[position[y]] = results[y]
print(final)
x = sorted(final.items(), key=lambda x: x[0])
print(''.join([y[1] for y in x]))
```

And finally we get: `utflag{m4Ch1nE_1rNg_SUx_LMFa0000000}`
