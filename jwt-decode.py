import jwt

token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmbGFnIjoiQlRMe180X0V5ZXN9IiwiaWF0Ijo5MDAwMDAwMCwibmFtZSI6IkdyZWF0RXhwIiwiYWRtaW4iOnRydWV9.jbkZHll_W17BOALT95JQ17glHBj9nY-oWhT1uiahtv8'

# decode without verification (not recommended for production use)
decoded = jwt.decode(token, options={"verify_signature": False})

print(decoded)
