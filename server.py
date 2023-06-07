from dossierapp import app
if __name__ == '__main__':
    app.run(debug=True, port=8080) 




# <input type="hidden" name="csrf_token" id="csrf_token" value="{{csrf_token()}}">
