<template>
  <div class='row'>
    <div class='offset-md-3 col-md-4'>
        <h1>Upload File and Code</h1>
        <form @submit.prevent='onSubmit()'>
          <div class="form-group">
            <label for="usr">File:</label>
            <input type="file" id="file"  class="form-control" ref="file">
          </div>
          <div class="form-group">
            <label for="pwd">Code:</label>
            <input type="text" name="code" class="form-control" v-model='code'>
          </div>
          <div class="form-group">
            <button type="submit" class="btn btn-primary form-control">Submit</button>
          </div>
      </form>
    </div>
  </div>
</template>

<script>
    export default {
        data(){
          return {
            file: '',
            code: 'eWbEy0BfEzkG/z9NOKwvlrLg3w2QIvN93SqxQ9Pk+iU='
          }
        },
        methods: {
          onSubmit(){
            if(this.$data.code != ''){
              this.file = this.$refs.file.files[0];
              this.$refs.file.value = '';

              if(this.file != null){
                let formData = new FormData();
                formData.append('file', this.file);
                formData.append('code', this.code);

                axios.post( '/encrypt',
                    formData,
                    {
                    headers: {
                        'Content-Type': 'multipart/form-data'
                    }
                  }
                ).then(function(response){
                  console.log(response);
                  if(response.data['error'] == 'true'){
                    alert(response.data['message']);
                  }else{
                    var element = document.createElement('a');
                    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(response.data['message']));
                    element.setAttribute('download', response.data['error']);
                    element.style.display = 'none';
                    document.body.appendChild(element);
                    element.click();
                    document.body.removeChild(element);
                  }
                })
                .catch(function(response){
                  console.log(response);
                });
              }else{
                alert('Please select file');
              }
            }else{
              alert('Code Field must be fill');
            }
          }
        },
        mounted() {
            console.log('Component mounted.')
        }
    }
</script>
