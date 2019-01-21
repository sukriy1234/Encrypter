<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <link href = "//maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap.min.css" rel = "stylesheet">
    <title>Upload File</title>
  </head>
  <body>
    <div class="container" id='app'>
      <example></example>
    </div>
    <!-- <form action="/coba0" method="POST" enctype="multipart/form-data">
        {{ csrf_field() }}
        <input type="file" name="file" />
        <br /><br />
        <input type="submit" value=" Save " />
    </form> -->
    <script src="{{ asset('js/app.js') }}"></script>
  </body>
</html>
