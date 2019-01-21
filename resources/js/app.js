require('./bootstrap');
import Vue from 'vue';

//default component
Vue.component(
  'example',
  require('./components/ExampleComponent.vue').default
);

const app = new Vue({
    el: '#app',
});
