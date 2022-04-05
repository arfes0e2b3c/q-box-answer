exports.ids = [4,1,2,3];
exports.modules = Array(25).concat([
/* 25 */
/***/ (function(module, exports, __webpack_require__) {

// style-loader: Adds some css to the DOM by adding a <style> tag

// load the styles
var content = __webpack_require__(28);
if(content.__esModule) content = content.default;
if(typeof content === 'string') content = [[module.i, content, '']];
if(content.locals) module.exports = content.locals;
// add CSS to SSR context
var add = __webpack_require__(9).default
module.exports.__inject__ = function (context) {
  add("364dbc90", content, true, context)
};

/***/ }),
/* 26 */
/***/ (function(module, exports, __webpack_require__) {

if (true) {
    module.exports = OAuth;
}

/**
 * Constructor
 * @param {Object} opts consumer key and secret
 */
function OAuth(opts) {
    if(!(this instanceof OAuth)) {
        return new OAuth(opts);
    }

    if(!opts) {
        opts = {};
    }

    if(!opts.consumer) {
        throw new Error('consumer option is required');
    }

    this.consumer            = opts.consumer;
    this.nonce_length        = opts.nonce_length || 32;
    this.version             = opts.version || '1.0';
    this.parameter_seperator = opts.parameter_seperator || ', ';
    this.realm               = opts.realm;

    if(typeof opts.last_ampersand === 'undefined') {
        this.last_ampersand = true;
    } else {
        this.last_ampersand = opts.last_ampersand;
    }

    // default signature_method is 'PLAINTEXT'
    this.signature_method = opts.signature_method || 'PLAINTEXT';

    if(this.signature_method == 'PLAINTEXT' && !opts.hash_function) {
        opts.hash_function = function(base_string, key) {
            return key;
        }
    }

    if(!opts.hash_function) {
        throw new Error('hash_function option is required');
    }

    this.hash_function = opts.hash_function;
    this.body_hash_function = opts.body_hash_function || this.hash_function;
}

/**
 * OAuth request authorize
 * @param  {Object} request data
 * {
 *     method,
 *     url,
 *     data
 * }
 * @param  {Object} key and secret token
 * @return {Object} OAuth Authorized data
 */
OAuth.prototype.authorize = function(request, token) {
    var oauth_data = {
        oauth_consumer_key: this.consumer.key,
        oauth_nonce: this.getNonce(),
        oauth_signature_method: this.signature_method,
        oauth_timestamp: this.getTimeStamp(),
        oauth_version: this.version
    };

    if(!token) {
        token = {};
    }

    if(token.key !== undefined) {
        oauth_data.oauth_token = token.key;
    }

    if(!request.data) {
        request.data = {};
    }

    if(request.includeBodyHash) {
      oauth_data.oauth_body_hash = this.getBodyHash(request, token.secret)
    }

    oauth_data.oauth_signature = this.getSignature(request, token.secret, oauth_data);

    return oauth_data;
};

/**
 * Create a OAuth Signature
 * @param  {Object} request data
 * @param  {Object} token_secret key and secret token
 * @param  {Object} oauth_data   OAuth data
 * @return {String} Signature
 */
OAuth.prototype.getSignature = function(request, token_secret, oauth_data) {
    return this.hash_function(this.getBaseString(request, oauth_data), this.getSigningKey(token_secret));
};

/**
 * Create a OAuth Body Hash
 * @param {Object} request data
 */
OAuth.prototype.getBodyHash = function(request, token_secret) {
  var body = typeof request.data === 'string' ? request.data : JSON.stringify(request.data)

  if (!this.body_hash_function) {
    throw new Error('body_hash_function option is required');
  }

  return this.body_hash_function(body, this.getSigningKey(token_secret))
};

/**
 * Base String = Method + Base Url + ParameterString
 * @param  {Object} request data
 * @param  {Object} OAuth data
 * @return {String} Base String
 */
OAuth.prototype.getBaseString = function(request, oauth_data) {
    return request.method.toUpperCase() + '&' + this.percentEncode(this.getBaseUrl(request.url)) + '&' + this.percentEncode(this.getParameterString(request, oauth_data));
};

/**
 * Get data from url
 * -> merge with oauth data
 * -> percent encode key & value
 * -> sort
 *
 * @param  {Object} request data
 * @param  {Object} OAuth data
 * @return {Object} Parameter string data
 */
OAuth.prototype.getParameterString = function(request, oauth_data) {
    var base_string_data;
    if (oauth_data.oauth_body_hash) {
        base_string_data = this.sortObject(this.percentEncodeData(this.mergeObject(oauth_data, this.deParamUrl(request.url))));
    } else {
        base_string_data = this.sortObject(this.percentEncodeData(this.mergeObject(oauth_data, this.mergeObject(request.data, this.deParamUrl(request.url)))));
    }

    var data_str = '';

    //base_string_data to string
    for(var i = 0; i < base_string_data.length; i++) {
        var key = base_string_data[i].key;
        var value = base_string_data[i].value;
        // check if the value is an array
        // this means that this key has multiple values
        if (value && Array.isArray(value)){
          // sort the array first
          value.sort();

          var valString = "";
          // serialize all values for this key: e.g. formkey=formvalue1&formkey=formvalue2
          value.forEach((function(item, i){
            valString += key + '=' + item;
            if (i < value.length){
              valString += "&";
            }
          }).bind(this));
          data_str += valString;
        } else {
          data_str += key + '=' + value + '&';
        }
    }

    //remove the last character
    data_str = data_str.substr(0, data_str.length - 1);
    return data_str;
};

/**
 * Create a Signing Key
 * @param  {String} token_secret Secret Token
 * @return {String} Signing Key
 */
OAuth.prototype.getSigningKey = function(token_secret) {
    token_secret = token_secret || '';

    if(!this.last_ampersand && !token_secret) {
        return this.percentEncode(this.consumer.secret);
    }

    return this.percentEncode(this.consumer.secret) + '&' + this.percentEncode(token_secret);
};

/**
 * Get base url
 * @param  {String} url
 * @return {String}
 */
OAuth.prototype.getBaseUrl = function(url) {
    return url.split('?')[0];
};

/**
 * Get data from String
 * @param  {String} string
 * @return {Object}
 */
OAuth.prototype.deParam = function(string) {
    var arr = string.split('&');
    var data = {};

    for(var i = 0; i < arr.length; i++) {
        var item = arr[i].split('=');

        // '' value
        item[1] = item[1] || '';

        // check if the key already exists
        // this can occur if the QS part of the url contains duplicate keys like this: ?formkey=formvalue1&formkey=formvalue2
        if (data[item[0]]){
          // the key exists already
          if (!Array.isArray(data[item[0]])) {
            // replace the value with an array containing the already present value
            data[item[0]] = [data[item[0]]];
          }
          // and add the new found value to it
          data[item[0]].push(decodeURIComponent(item[1]));
        } else {
          // it doesn't exist, just put the found value in the data object
          data[item[0]] = decodeURIComponent(item[1]);
        }
    }

    return data;
};

/**
 * Get data from url
 * @param  {String} url
 * @return {Object}
 */
OAuth.prototype.deParamUrl = function(url) {
    var tmp = url.split('?');

    if (tmp.length === 1)
        return {};

    return this.deParam(tmp[1]);
};

/**
 * Percent Encode
 * @param  {String} str
 * @return {String} percent encoded string
 */
OAuth.prototype.percentEncode = function(str) {
    return encodeURIComponent(str)
        .replace(/\!/g, "%21")
        .replace(/\*/g, "%2A")
        .replace(/\'/g, "%27")
        .replace(/\(/g, "%28")
        .replace(/\)/g, "%29");
};

/**
 * Percent Encode Object
 * @param  {Object} data
 * @return {Object} percent encoded data
 */
OAuth.prototype.percentEncodeData = function(data) {
    var result = {};

    for(var key in data) {
        var value = data[key];
        // check if the value is an array
        if (value && Array.isArray(value)){
          var newValue = [];
          // percentEncode every value
          value.forEach((function(val){
            newValue.push(this.percentEncode(val));
          }).bind(this));
          value = newValue;
        } else {
          value = this.percentEncode(value);
        }
        result[this.percentEncode(key)] = value;
    }

    return result;
};

/**
 * Get OAuth data as Header
 * @param  {Object} oauth_data
 * @return {String} Header data key - value
 */
OAuth.prototype.toHeader = function(oauth_data) {
    var sorted = this.sortObject(oauth_data);

    var header_value = 'OAuth ';

    if (this.realm) {
        header_value += 'realm="' + this.realm + '"' + this.parameter_seperator;
    }

    for(var i = 0; i < sorted.length; i++) {
        if (sorted[i].key.indexOf('oauth_') !== 0)
            continue;

        header_value += this.percentEncode(sorted[i].key) + '="' + this.percentEncode(sorted[i].value) + '"' + this.parameter_seperator;
    }

    return {
        Authorization: header_value.substr(0, header_value.length - this.parameter_seperator.length) //cut the last chars
    };
};

/**
 * Create a random word characters string with input length
 * @return {String} a random word characters string
 */
OAuth.prototype.getNonce = function() {
    var word_characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    var result = '';

    for(var i = 0; i < this.nonce_length; i++) {
        result += word_characters[parseInt(Math.random() * word_characters.length, 10)];
    }

    return result;
};

/**
 * Get Current Unix TimeStamp
 * @return {Int} current unix timestamp
 */
OAuth.prototype.getTimeStamp = function() {
    return parseInt(new Date().getTime()/1000, 10);
};

////////////////////// HELPER FUNCTIONS //////////////////////

/**
 * Merge object
 * @param  {Object} obj1
 * @param  {Object} obj2
 * @return {Object}
 */
OAuth.prototype.mergeObject = function(obj1, obj2) {
    obj1 = obj1 || {};
    obj2 = obj2 || {};

    var merged_obj = obj1;
    for(var key in obj2) {
        merged_obj[key] = obj2[key];
    }
    return merged_obj;
};

/**
 * Sort object by key
 * @param  {Object} data
 * @return {Array} sorted array
 */
OAuth.prototype.sortObject = function(data) {
    var keys = Object.keys(data);
    var result = [];

    keys.sort();

    for(var i = 0; i < keys.length; i++) {
        var key = keys[i];
        result.push({
            key: key,
            value: data[key],
        });
    }

    return result;
};


/***/ }),
/* 27 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SendSentence_vue_vue_type_style_index_0_id_218f8c1e_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(25);
/* harmony import */ var _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SendSentence_vue_vue_type_style_index_0_id_218f8c1e_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SendSentence_vue_vue_type_style_index_0_id_218f8c1e_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__);
/* harmony reexport (unknown) */ for(var __WEBPACK_IMPORT_KEY__ in _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SendSentence_vue_vue_type_style_index_0_id_218f8c1e_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__) if(["default"].indexOf(__WEBPACK_IMPORT_KEY__) < 0) (function(key) { __webpack_require__.d(__webpack_exports__, key, function() { return _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SendSentence_vue_vue_type_style_index_0_id_218f8c1e_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__[key]; }) }(__WEBPACK_IMPORT_KEY__));


/***/ }),
/* 28 */
/***/ (function(module, exports, __webpack_require__) {

// Imports
var ___CSS_LOADER_API_IMPORT___ = __webpack_require__(8);
var ___CSS_LOADER_EXPORT___ = ___CSS_LOADER_API_IMPORT___(false);
// Module
___CSS_LOADER_EXPORT___.push([module.i, ".sentence-box[data-v-218f8c1e]{width:calc(100% - 40px);height:150px;display:flex;flex-direction:column;align-items:center;transition:.5s;padding-top:20px;overflow:hidden}.sentence-box h3[data-v-218f8c1e]{margin:10px auto}.sentence-box textarea[data-v-218f8c1e]{resize:none;width:calc(80% - 40px);height:30px;padding:20px;outline:none;border-color:rgba(0,0,0,.15);border-width:2px;border-radius:10px}.sentence-box button[data-v-218f8c1e]{width:80px;height:30px;margin-top:10px;border:1px solid rgba(0,0,0,.3);border-radius:5px;background:none;transition:.5s;cursor:pointer}.sentence-box button[data-v-218f8c1e]:hover{background-color:#77d;border:1px solid #0000c8;color:#fff}.held .button[data-v-218f8c1e]{color:#fff;border:1px solid #fff}.boxHeightInPosts[data-v-218f8c1e]{height:114px}.v-enter[data-v-218f8c1e]{opacity:0;height:0;padding-top:0}.v-enter-to[data-v-218f8c1e]{opacity:1;height:150px;padding-top:20px}.v-enter-active[data-v-218f8c1e]{transition:.5s}.v-leave[data-v-218f8c1e]{opacity:1;padding-top:20px}.v-leave-to[data-v-218f8c1e]{opacity:0;height:0;padding-top:0}.v-leave-active[data-v-218f8c1e]{transition:.5s}@media (max-width:520px){.sentence-box[data-v-218f8c1e]{width:100%;padding-top:10px}.sentence-box h3[data-v-218f8c1e]{font-size:1em}.sentence-box textarea[data-v-218f8c1e]{width:calc(90% - 40px);padding:10px}.boxHeightInPosts[data-v-218f8c1e]{height:94px}.v-enter[data-v-218f8c1e]{opacity:0;height:0;padding-top:0}.v-enter-to[data-v-218f8c1e]{opacity:1;padding-top:10px;height:150px}.v-enter-active[data-v-218f8c1e]{transition:.5s}.v-leave[data-v-218f8c1e]{opacity:1;padding-top:10px;height:150px}.v-leave-to[data-v-218f8c1e]{opacity:0;height:0;padding-top:0}.v-leave-active[data-v-218f8c1e]{transition:opacity .1s,padding-top .5s,height .5s}}", ""]);
// Exports
module.exports = ___CSS_LOADER_EXPORT___;


/***/ }),
/* 29 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// CONCATENATED MODULE: ./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/@nuxt/components/dist/loader.js??ref--0-0!./node_modules/vue-loader/lib??vue-loader-options!./components/shared/SendSentence.vue?vue&type=template&id=218f8c1e&scoped=true&
var render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('transition',[_c('div',{directives:[{name:"show",rawName:"v-show",value:(_vm.getShow),expression:"getShow"}],staticClass:"sentence-box",class:{ held: this.held, boxHeightInPosts: _vm.getMode === 'reply' }},[_c('h3',{directives:[{name:"show",rawName:"v-show",value:(_vm.getMode === 'question'),expression:"getMode === 'question'"}]},[_vm._v("質問する")]),_vm._v(" "),_c('textarea',{directives:[{name:"model",rawName:"v-model",value:(_vm.sentence),expression:"sentence"}],attrs:{"placeholder":this.textareaWord[_vm.mode],"autocomplete":"off"},domProps:{"value":(_vm.sentence)},on:{"input":function($event){if($event.target.composing){ return; }_vm.sentence=$event.target.value}}}),_vm._v(" "),_c('p',{directives:[{name:"show",rawName:"v-show",value:(_vm.getMode === 'answer' || _vm.getMode === 'replyForReply'),expression:"getMode === 'answer' || getMode === 'replyForReply'"}]},[_vm._v("\n      "+_vm._s(this.sentence.length)+"\n    ")]),_vm._v(" "),_c('button',{staticClass:"button",on:{"click":function($event){return _vm.sendSentence()}}},[_vm._v("\n      "+_vm._s(this.buttonWord[_vm.mode])+"\n    ")])])])}
var staticRenderFns = []


// CONCATENATED MODULE: ./components/shared/SendSentence.vue?vue&type=template&id=218f8c1e&scoped=true&

// EXTERNAL MODULE: ./node_modules/oauth-1.0a/oauth-1.0a.js
var oauth_1_0a = __webpack_require__(26);
var oauth_1_0a_default = /*#__PURE__*/__webpack_require__.n(oauth_1_0a);

// EXTERNAL MODULE: external "crypto"
var external_crypto_ = __webpack_require__(24);
var external_crypto_default = /*#__PURE__*/__webpack_require__.n(external_crypto_);

// CONCATENATED MODULE: ./node_modules/babel-loader/lib??ref--2-0!./node_modules/@nuxt/components/dist/loader.js??ref--0-0!./node_modules/vue-loader/lib??vue-loader-options!./components/shared/SendSentence.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//


/* harmony default export */ var SendSentencevue_type_script_lang_js_ = ({
  props: {
    mode: "",
    contentId: "",
    replyTweetId: "",
    contentOriginId: "",
    replySentence: "",
    held: false,
    show: "",
    MICROCMS_KEY: "",
    CONSUMER_KEY: "",
    CONSUMER_KEY_SECRET: "",
    ACCESS_TOKEN_KEY: "",
    ACCESS_TOKEN_KEY_SECRET: ""
  },

  data() {
    return {
      getShow: this.show,
      getMode: this.mode,
      getContentId: this.contentId,
      getReplyTweetId: this.replyTweetId,
      getContentOriginId: this.contentOriginId,
      getReplySentence: this.replySentence,
      sentence: "",
      textareaWord: {
        question: "質問を入力する",
        answer: "この質問への回答を入力する",
        reply: "この質問への返信を入力する",
        replyForReply: "この返信への回答を入力する"
      },
      buttonWord: {
        question: "質問する",
        answer: "回答する",
        reply: "返信する",
        replyForReply: "回答する"
      }
    };
  },

  methods: {
    toggle() {
      this.getShow = !this.getShow;
    },

    async sendSentence() {
      if (this.sentence && this.getMode === "answer") {
        this.postTweet(this.sentence, this.getContentId, "tweet", "answer");
      } else if (this.sentence && this.getMode === "replyForReply") {
        this.postTweet("【フォロワーの方からの情報】\n\n" + this.getReplySentence + "\n\n" + this.sentence, this.getReplyTweetId, "reply", "replyForReply");
        this.$emit("setReply");
      }
    },

    async postTweet(answer, id, mode, sendSentenceMode) {
      console.log("posttweet", answer, id);
      const TWEET_LIMIT_CHARS_INCLUDE_URL = 110;
      const TWEET_LIMIT_CHARS = 140;
      let slicedAnswer = [...answer];

      if (!Array.isArray(answer)) {
        slicedAnswer = [];
        slicedAnswer.push(answer.slice(0, TWEET_LIMIT_CHARS_INCLUDE_URL));

        for (let i = TWEET_LIMIT_CHARS_INCLUDE_URL; i < answer.length - 2; i += TWEET_LIMIT_CHARS) {
          slicedAnswer.push(answer.slice(i, i + TWEET_LIMIT_CHARS));
        }
      }

      const oauth = oauth_1_0a_default()({
        consumer: {
          key: this.CONSUMER_KEY,
          secret: this.CONSUMER_KEY_SECRET
        },
        signature_method: "HMAC-SHA1",

        hash_function(base_string, key) {
          return external_crypto_default.a.createHmac("sha1", key).update(base_string).digest("base64");
        }

      });
      const token = {
        key: this.ACCESS_TOKEN_KEY,
        secret: this.ACCESS_TOKEN_KEY_SECRET
      };
      const request = {
        url: "https://api.twitter.com/2/tweets",
        method: "POST"
      };
      let config = oauth.toHeader(oauth.authorize(request, token)).Authorization;
      let data = {};

      if (mode === "tweet") {
        data = {
          text: slicedAnswer[0] + "\nhttps://unique-donut-e9d728.netlify.app/" + id
        };
      } else if (mode === "reply") {
        data = {
          text: slicedAnswer[0],
          reply: {
            in_reply_to_tweet_id: id
          }
        };
      } else {
        console.log("not fit!");
      }

      await this.$axios.$post("/api/2/tweets", data, {
        headers: {
          authorization: config
        }
      }).then(response => {
        if (slicedAnswer.length > 1) {
          this.postTweet(slicedAnswer.slice(1), response.data.id, "reply");
        }

        if (sendSentenceMode === "answer") {
          this.sendSentenceModeAnswer(response.data.id);
        } else if (sendSentenceMode === "replyForReply") {
          this.sendSentenceModeReplyForReply(response.data.id);
          this.setReplyTweetId(response.data.id);
        }
      }).catch(error => {
        alert("通信に失敗しました。：" + error);
        console.log(error);
      });
    },

    async sendSentenceModeAnswer(id) {
      await this.$axios.$patch("https://q-box.microcms.io/api/v1/q_box_posts/" + this.getContentId, {
        answer: this.sentence,
        replyTweetId: id
      }, {
        headers: {
          "Content-Type": "application/json",
          "X-MICROCMS-API-KEY": this.MICROCMS_KEY
        }
      }).catch(error => {
        alert("通信に失敗しました。：" + error);
        console.log(error);
      }).then(() => {
        this.$emit("get-posts");
        this.sentence = "";
      });
    },

    async sendSentenceModeReplyForReply() {
      await this.$axios.$patch("https://q-box.microcms.io/api/v1/q_box_replies/" + this.getContentId, {
        replyAnswer: this.sentence
      }, {
        headers: {
          "Content-Type": "application/json",
          "X-MICROCMS-API-KEY": this.MICROCMS_KEY
        }
      }).then(() => {
        this.$emit("set-replies");
        this.sentence = "";
      }).catch(error => {
        alert("通信に失敗しました。：" + error);
        console.log(error);
      });
    },

    async setReplyTweetId(id) {
      await this.$axios.$patch("https://q-box.microcms.io/api/v1/q_box_posts/" + this.getContentOriginId, {
        replyTweetId: id
      }, {
        headers: {
          "Content-Type": "application/json",
          "X-MICROCMS-API-KEY": this.MICROCMS_KEY
        }
      }).catch(error => {
        alert("通信に失敗しました。：" + error);
        console.log(error);
      });
    }

  }
});
// CONCATENATED MODULE: ./components/shared/SendSentence.vue?vue&type=script&lang=js&
 /* harmony default export */ var shared_SendSentencevue_type_script_lang_js_ = (SendSentencevue_type_script_lang_js_); 
// EXTERNAL MODULE: ./node_modules/vue-loader/lib/runtime/componentNormalizer.js
var componentNormalizer = __webpack_require__(2);

// CONCATENATED MODULE: ./components/shared/SendSentence.vue



function injectStyles (context) {
  
  var style0 = __webpack_require__(27)
if (style0.__inject__) style0.__inject__(context)

}

/* normalize component */

var component = Object(componentNormalizer["a" /* default */])(
  shared_SendSentencevue_type_script_lang_js_,
  render,
  staticRenderFns,
  false,
  injectStyles,
  "218f8c1e",
  "2a8c5b16"
  
)

/* harmony default export */ var SendSentence = __webpack_exports__["default"] = (component.exports);

/***/ }),
/* 30 */
/***/ (function(module, exports, __webpack_require__) {

// style-loader: Adds some css to the DOM by adding a <style> tag

// load the styles
var content = __webpack_require__(33);
if(content.__esModule) content = content.default;
if(typeof content === 'string') content = [[module.i, content, '']];
if(content.locals) module.exports = content.locals;
// add CSS to SSR context
var add = __webpack_require__(9).default
module.exports.__inject__ = function (context) {
  add("797b4eda", content, true, context)
};

/***/ }),
/* 31 */
/***/ (function(module, exports, __webpack_require__) {

// style-loader: Adds some css to the DOM by adding a <style> tag

// load the styles
var content = __webpack_require__(35);
if(content.__esModule) content = content.default;
if(typeof content === 'string') content = [[module.i, content, '']];
if(content.locals) module.exports = content.locals;
// add CSS to SSR context
var add = __webpack_require__(9).default
module.exports.__inject__ = function (context) {
  add("19728754", content, true, context)
};

/***/ }),
/* 32 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_AnswerWaitPost_vue_vue_type_style_index_0_id_29b0eea8_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(30);
/* harmony import */ var _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_AnswerWaitPost_vue_vue_type_style_index_0_id_29b0eea8_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_AnswerWaitPost_vue_vue_type_style_index_0_id_29b0eea8_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__);
/* harmony reexport (unknown) */ for(var __WEBPACK_IMPORT_KEY__ in _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_AnswerWaitPost_vue_vue_type_style_index_0_id_29b0eea8_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__) if(["default"].indexOf(__WEBPACK_IMPORT_KEY__) < 0) (function(key) { __webpack_require__.d(__webpack_exports__, key, function() { return _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_AnswerWaitPost_vue_vue_type_style_index_0_id_29b0eea8_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__[key]; }) }(__WEBPACK_IMPORT_KEY__));


/***/ }),
/* 33 */
/***/ (function(module, exports, __webpack_require__) {

// Imports
var ___CSS_LOADER_API_IMPORT___ = __webpack_require__(8);
var ___CSS_LOADER_EXPORT___ = ___CSS_LOADER_API_IMPORT___(false);
// Module
___CSS_LOADER_EXPORT___.push([module.i, "header[data-v-29b0eea8]{width:100%;height:70px;display:flex;justify-content:center;align-items:center}ul[data-v-29b0eea8]{width:80%;margin:0 auto}ul>div[data-v-29b0eea8]{display:flex;margin:10px 0}ul h2[data-v-29b0eea8]{font-size:2.2em}ul li[data-v-29b0eea8]{flex-direction:column;list-style:none;box-shadow:0 0 5px 5px rgba(0,0,0,.1);padding:20px;margin:20px 0;word-wrap:break-word}ul li[data-v-29b0eea8],ul li .box[data-v-29b0eea8]{display:flex;align-items:center}ul li .box[data-v-29b0eea8]{width:100%;justify-content:space-between}ul li .box h3[data-v-29b0eea8]{width:70%;text-align:center;white-space:pre-wrap}ul li .box button[data-v-29b0eea8],ul li .box div button[data-v-29b0eea8]{width:50px;height:30px;border:1px solid rgba(0,0,0,.3);border-radius:5px;background:none;transition:.5s;cursor:pointer}ul li .box button[data-v-29b0eea8]:hover,ul li .box div button[data-v-29b0eea8]:hover{background-color:#d77;border:1px solid #c80000;color:#fff}ul li .box .toggle-button[data-v-29b0eea8]{width:100px}ul li .box .toggle-button[data-v-29b0eea8]:hover{background-color:#303030;border-color:#303030}ul .held[data-v-29b0eea8]{background-color:#333;color:#fff}ul .held .box div button[data-v-29b0eea8],ul .held div .toggle-button[data-v-29b0eea8]{color:#fff;border:1px solid #fff}ul .held div .toggle-button[data-v-29b0eea8]:hover{background-color:#fff;border:1px solid #fff;color:#303030}.flip-list-move[data-v-29b0eea8]{transition:transform .5s}@media (max-width:520px){ul[data-v-29b0eea8]{width:100%}ul div h2[data-v-29b0eea8]{font-size:1.6em;margin-left:10px}ul li[data-v-29b0eea8]{padding:10px;margin:10px 0}ul li .box h3[data-v-29b0eea8]{width:auto;font-size:1em;max-width:calc(100% - 120px)}ul li .box div[data-v-29b0eea8]{width:50px}ul li .box div button[data-v-29b0eea8]{margin:5px 0}ul li .box .toggle-button[data-v-29b0eea8]{width:50px;height:70px}}", ""]);
// Exports
module.exports = ___CSS_LOADER_EXPORT___;


/***/ }),
/* 34 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_AnswerWaitReply_vue_vue_type_style_index_0_id_24fe3ecd_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(31);
/* harmony import */ var _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_AnswerWaitReply_vue_vue_type_style_index_0_id_24fe3ecd_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_AnswerWaitReply_vue_vue_type_style_index_0_id_24fe3ecd_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__);
/* harmony reexport (unknown) */ for(var __WEBPACK_IMPORT_KEY__ in _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_AnswerWaitReply_vue_vue_type_style_index_0_id_24fe3ecd_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__) if(["default"].indexOf(__WEBPACK_IMPORT_KEY__) < 0) (function(key) { __webpack_require__.d(__webpack_exports__, key, function() { return _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_AnswerWaitReply_vue_vue_type_style_index_0_id_24fe3ecd_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__[key]; }) }(__WEBPACK_IMPORT_KEY__));


/***/ }),
/* 35 */
/***/ (function(module, exports, __webpack_require__) {

// Imports
var ___CSS_LOADER_API_IMPORT___ = __webpack_require__(8);
var ___CSS_LOADER_EXPORT___ = ___CSS_LOADER_API_IMPORT___(false);
// Module
___CSS_LOADER_EXPORT___.push([module.i, "header[data-v-24fe3ecd]{width:100%;height:70px;border:1px solid red;display:flex;justify-content:center;align-items:center}ul[data-v-24fe3ecd]{width:80%;margin:0 auto}ul h2[data-v-24fe3ecd]{font-size:2.2em}ul li[data-v-24fe3ecd]{list-style:none;margin:20px 0;padding:20px;display:flex;align-items:center;flex-direction:column;box-shadow:0 0 5px 5px rgba(0,0,0,.1);word-wrap:break-word}ul li h3[data-v-24fe3ecd]{white-space:pre-wrap;text-align:center;margin-bottom:30px;color:red}ul li h3[data-v-24fe3ecd],ul li p[data-v-24fe3ecd]{width:70%;text-align:center}ul li>div[data-v-24fe3ecd]{width:90%;display:flex;align-items:center;flex-direction:column;box-shadow:0 0 5px 5px rgba(0,0,0,.1);padding:20px;margin:10px 0}ul li>div .manage-send-sentence-box[data-v-24fe3ecd]{width:100%;display:flex;justify-content:space-between;align-items:center}ul li>div .manage-send-sentence-box button[data-v-24fe3ecd],ul li>div .manage-send-sentence-box div button[data-v-24fe3ecd]{width:50px;height:30px;border:1px solid rgba(0,0,0,.3);border-radius:5px;background:none;transition:.5s;cursor:pointer}ul li>div .manage-send-sentence-box button[data-v-24fe3ecd]:hover,ul li>div .manage-send-sentence-box div button[data-v-24fe3ecd]:hover{background-color:#d77;border:1px solid #c80000;color:#fff}ul li>div .manage-send-sentence-box .toggle-button[data-v-24fe3ecd]{width:100px}ul li>div .manage-send-sentence-box .toggle-button[data-v-24fe3ecd]:hover{background-color:#303030;border:1px solid #fff}ul li>div .manage-send-sentence-box h4[data-v-24fe3ecd]{width:70%;white-space:pre-wrap;text-align:center}ul li .held[data-v-24fe3ecd]{background-color:#333;color:#fff}ul li .held .toggle-button[data-v-24fe3ecd],ul li .held div div button[data-v-24fe3ecd]{color:#fff;border:1px solid #fff}ul li .held .toggle-button[data-v-24fe3ecd]:hover{background-color:#fff;color:#303030}p[data-v-24fe3ecd]{margin:5px 0}@media (max-width:520px){ul[data-v-24fe3ecd]{width:100%}ul h2[data-v-24fe3ecd]{font-size:1.6em;margin-left:10px}ul li[data-v-24fe3ecd]{padding:20px 10px;margin:10px 0}ul li h3[data-v-24fe3ecd]{margin-bottom:10px}ul li h3[data-v-24fe3ecd],ul li p[data-v-24fe3ecd]{width:90%}ul li>div[data-v-24fe3ecd]{margin:5px 0;padding:10px}ul li>div .manage-send-sentence-box div[data-v-24fe3ecd]{width:50px}ul li>div .manage-send-sentence-box div button[data-v-24fe3ecd]{margin:5px 0}ul li>div .manage-send-sentence-box h4[data-v-24fe3ecd]{max-width:calc(100% - 120px)}ul li>div .manage-send-sentence-box .toggle-button[data-v-24fe3ecd]{width:50px;height:70px}}", ""]);
// Exports
module.exports = ___CSS_LOADER_EXPORT___;


/***/ }),
/* 36 */
/***/ (function(module, exports, __webpack_require__) {

// style-loader: Adds some css to the DOM by adding a <style> tag

// load the styles
var content = __webpack_require__(41);
if(content.__esModule) content = content.default;
if(typeof content === 'string') content = [[module.i, content, '']];
if(content.locals) module.exports = content.locals;
// add CSS to SSR context
var add = __webpack_require__(9).default
module.exports.__inject__ = function (context) {
  add("1b7833da", content, true, context)
};

/***/ }),
/* 37 */
/***/ (function(module, exports, __webpack_require__) {

// style-loader: Adds some css to the DOM by adding a <style> tag

// load the styles
var content = __webpack_require__(45);
if(content.__esModule) content = content.default;
if(typeof content === 'string') content = [[module.i, content, '']];
if(content.locals) module.exports = content.locals;
// add CSS to SSR context
var add = __webpack_require__(9).default
module.exports.__inject__ = function (context) {
  add("943f4c24", content, true, context)
};

/***/ }),
/* 38 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// CONCATENATED MODULE: ./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/@nuxt/components/dist/loader.js??ref--0-0!./node_modules/vue-loader/lib??vue-loader-options!./components/AnswerWaitPost.vue?vue&type=template&id=29b0eea8&scoped=true&
var render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('ul',[_vm._ssrNode("<div data-v-29b0eea8><h2 data-v-29b0eea8>未回答の質問(古い順)</h2> <button data-v-29b0eea8>保留のみ表示</button></div> <p"+(_vm._ssrStyle(null,null, { display: (!_vm.posts[0]) ? '' : 'none' }))+" data-v-29b0eea8>質問はありません</p> "),_c('transition-group',{attrs:{"name":"flip-list"}},_vm._l((_vm.posts),function(post){return _c('li',{key:post.id,class:{ held: post.held }},[_c('div',{staticClass:"box"},[_c('div',[_c('button',{on:{"click":function($event){return _vm.deletePost(post.id)}}},[_vm._v("削除")]),_vm._v(" "),_c('button',{on:{"click":function($event){return _vm.holdPost(post.id, post.held)}}},[_vm._v("保留")])]),_vm._v(" "),_c('h3',[_vm._v(_vm._s(post.question))]),_vm._v(" "),_c('button',{staticClass:"toggle-button",on:{"click":function($event){return _vm.showSendSentence(post.id)}}},[_vm._v("\n          開閉\n        ")])]),_vm._v(" "),_c('SharedSendSentence',{ref:post.id,refInFor:true,staticClass:"send-sentence",attrs:{"mode":_vm.modeAnswer,"content-id":post.id,"held":post.held,"show":false,"MICROCMS_KEY":_vm.MICROCMS_KEY,"CONSUMER_KEY":_vm.CONSUMER_KEY,"CONSUMER_KEY_SECRET":_vm.CONSUMER_KEY_SECRET,"ACCESS_TOKEN_KEY":_vm.ACCESS_TOKEN_KEY,"ACCESS_TOKEN_KEY_SECRET":_vm.ACCESS_TOKEN_KEY_SECRET},on:{"get-posts":_vm.getPosts}})],1)}),0)],2)}
var staticRenderFns = []


// CONCATENATED MODULE: ./components/AnswerWaitPost.vue?vue&type=template&id=29b0eea8&scoped=true&

// EXTERNAL MODULE: ./plugins/common.js
var common = __webpack_require__(5);

// CONCATENATED MODULE: ./node_modules/babel-loader/lib??ref--2-0!./node_modules/@nuxt/components/dist/loader.js??ref--0-0!./node_modules/vue-loader/lib??vue-loader-options!./components/AnswerWaitPost.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//

/* harmony default export */ var AnswerWaitPostvue_type_script_lang_js_ = ({
  data() {
    return {
      posts: [],
      modeAnswer: "answer",
      heldOnly: false,
      MICROCMS_KEY: "",
      CONSUMER_KEY: "",
      CONSUMER_KEY_SECRET: "",
      ACCESS_TOKEN_KEY: "",
      ACCESS_TOKEN_KEY_SECRET: ""
    };
  },

  methods: {
    showSendSentence(id) {
      this.$refs[id][0].toggle();
    },

    async getPosts() {
      await this.$axios.$get("https://q-box.microcms.io/api/v1/q_box_posts?filters=answer[not_exists]&orders=createdAt", {
        headers: {
          "X-MICROCMS-API-KEY": this.MICROCMS_KEY
        }
      }).then(response => {
        this.$set(this, "posts", response.contents);
      }).catch(error => {
        alert("通信に失敗しました。：" + error);
        console.log(error);
      });
    },

    deletePost(id) {
      common["a" /* default */].deletePost(this, id, "q_box_posts", this.MICROCMS_KEY);
    },

    holdPost(id, held) {
      common["a" /* default */].holdPost(this, id, "q_box_posts", this.MICROCMS_KEY, held);
    },

    held() {
      if (!this.heldOnly) {
        this.posts.sort((first, second) => {
          return first.held === second.held ? 0 : first.held ? -1 : 1;
        });
      } else {
        this.posts.sort((first, second) => {
          return first.createdAt > second.createdAt ? 0 : -1;
        });
      }

      this.heldOnly = !this.heldOnly;
    }

  },

  async mounted() {
    this.MICROCMS_KEY = "f999ee3a5b064d859ee8072912dd0265ab9f";
    this.CONSUMER_KEY = "Kn7JSGK3ebklzfZKsAgq8A6BB";
    this.CONSUMER_KEY_SECRET = "Vsdsq0vosePrRgLbgVAMjco3Na4lFVQ8QiPUP3pwBp8gQG3lMe";
    this.ACCESS_TOKEN_KEY = "1494570525166690304-hdloI9h9Vw27OZraElbtWL9GF6XPBm";
    this.ACCESS_TOKEN_KEY_SECRET = "chgUBxGwAU3EI2njwyQXtXZZFw2tX7xAMdelA2zJuFBR3";
    this.getPosts();
  }

});
// CONCATENATED MODULE: ./components/AnswerWaitPost.vue?vue&type=script&lang=js&
 /* harmony default export */ var components_AnswerWaitPostvue_type_script_lang_js_ = (AnswerWaitPostvue_type_script_lang_js_); 
// EXTERNAL MODULE: ./node_modules/vue-loader/lib/runtime/componentNormalizer.js
var componentNormalizer = __webpack_require__(2);

// CONCATENATED MODULE: ./components/AnswerWaitPost.vue



function injectStyles (context) {
  
  var style0 = __webpack_require__(32)
if (style0.__inject__) style0.__inject__(context)

}

/* normalize component */

var component = Object(componentNormalizer["a" /* default */])(
  components_AnswerWaitPostvue_type_script_lang_js_,
  render,
  staticRenderFns,
  false,
  injectStyles,
  "29b0eea8",
  "9a40b1fa"
  
)

/* harmony default export */ var AnswerWaitPost = __webpack_exports__["default"] = (component.exports);

/* nuxt-component-imports */
installComponents(component, {SharedSendSentence: __webpack_require__(29).default})


/***/ }),
/* 39 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// CONCATENATED MODULE: ./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/@nuxt/components/dist/loader.js??ref--0-0!./node_modules/vue-loader/lib??vue-loader-options!./components/AnswerWaitReply.vue?vue&type=template&id=24fe3ecd&scoped=true&
var render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('ul',[_vm._ssrNode("<h2 data-v-24fe3ecd>未回答の返信</h2> <p"+(_vm._ssrStyle(null,null, { display: (!_vm.posts[0]) ? '' : 'none' }))+" data-v-24fe3ecd>質問はありません</p> "),_vm._l((_vm.posts),function(post){return _vm._ssrNode("<li data-v-24fe3ecd>","</li>",[_vm._ssrNode("<h3 data-v-24fe3ecd>"+_vm._ssrEscape(_vm._s(post.question))+"</h3> <p data-v-24fe3ecd>"+_vm._ssrEscape(_vm._s(post.answer))+"</p> "),_vm._l((post.replies),function(reply){return _vm._ssrNode("<div"+(_vm._ssrClass(null,{ held: reply.held }))+" data-v-24fe3ecd>","</div>",[_vm._ssrNode("<div class=\"manage-send-sentence-box\" data-v-24fe3ecd><div data-v-24fe3ecd><button data-v-24fe3ecd>削除</button> <button data-v-24fe3ecd>保留</button></div> <h4 data-v-24fe3ecd>"+_vm._ssrEscape(_vm._s(reply.replySentence))+"</h4> <button class=\"toggle-button\" data-v-24fe3ecd>\n          開閉\n        </button></div> "),_c('SharedSendSentence',{ref:reply.id,refInFor:true,attrs:{"mode":_vm.modeReplyForReply,"contentId":reply.id,"replyTweetId":post.replyTweetId,"contentOriginId":post.id,"replySentence":reply.replySentence,"show":false,"MICROCMS_KEY":_vm.MICROCMS_KEY,"CONSUMER_KEY":_vm.CONSUMER_KEY,"CONSUMER_KEY_SECRET":_vm.CONSUMER_KEY_SECRET,"ACCESS_TOKEN_KEY":_vm.ACCESS_TOKEN_KEY,"ACCESS_TOKEN_KEY_SECRET":_vm.ACCESS_TOKEN_KEY_SECRET},on:{"set-replies":_vm.setReply}})],2)})],2)})],2)}
var staticRenderFns = []


// CONCATENATED MODULE: ./components/AnswerWaitReply.vue?vue&type=template&id=24fe3ecd&scoped=true&

// EXTERNAL MODULE: ./plugins/common.js
var common = __webpack_require__(5);

// CONCATENATED MODULE: ./node_modules/babel-loader/lib??ref--2-0!./node_modules/@nuxt/components/dist/loader.js??ref--0-0!./node_modules/vue-loader/lib??vue-loader-options!./components/AnswerWaitReply.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//

/* harmony default export */ var AnswerWaitReplyvue_type_script_lang_js_ = ({
  data() {
    return {
      MICROCMS_KEY: "",
      CONSUMER_KEY: "",
      CONSUMER_KEY_SECRET: "",
      ACCESS_TOKEN_KEY: "",
      ACCESS_TOKEN_KEY_SECRET: "",
      replies: [],
      posts: [],
      modeReplyForReply: "replyForReply"
    };
  },

  methods: {
    showSendSentence(id) {
      this.$refs[id][0].toggle();
    },

    async setReply() {
      await this.$axios.$get("https://q-box.microcms.io/api/v1/q_box_replies?filters=replyAnswer[not_exists]&orders=createdAt", {
        headers: {
          "X-MICROCMS-API-KEY": this.MICROCMS_KEY
        }
      }).then(response => {
        const idList = this.makeIdList(response.contents);
        this.$set(this, "replies", response.contents);
        this.getPost(idList);
      }).catch(error => {
        alert("通信に失敗しました。：" + error);
        console.log(error);
      });
    },

    makeIdList(replies) {
      let idList = [];

      for (const reply of replies) {
        idList.push(reply.replyFor);
      }

      return idList.filter(function (x, i, self) {
        return self.indexOf(x) === i;
      });
    },

    async getPost(idList) {
      let postList = [];

      for (const id of idList) {
        await this.$axios.$get("https://q-box.microcms.io/api/v1/q_box_posts?filters=id[equals]" + id, {
          headers: {
            "X-MICROCMS-API-KEY": this.MICROCMS_KEY
          }
        }).then(response => {
          response.contents[0].replies = this.replies.filter(x => {
            if (x.replyFor === response.contents[0].id) {
              return x;
            }
          });
          postList.push(response.contents[0]);
        }).catch(error => {
          alert("通信に失敗しました。：" + error);
          console.log(error);
        });
      }

      this.$set(this, "posts", postList);
    },

    deletePost(id) {
      common["a" /* default */].deletePost(this, id, "q_box_replies", this.MICROCMS_KEY);
    },

    holdPost(id, held) {
      common["a" /* default */].holdPost(this, id, "q_box_replies", this.MICROCMS_KEY, held);
    }

  },

  mounted() {
    this.MICROCMS_KEY = "f999ee3a5b064d859ee8072912dd0265ab9f";
    this.CONSUMER_KEY = "Kn7JSGK3ebklzfZKsAgq8A6BB";
    this.CONSUMER_KEY_SECRET = "Vsdsq0vosePrRgLbgVAMjco3Na4lFVQ8QiPUP3pwBp8gQG3lMe";
    this.ACCESS_TOKEN_KEY = "1494570525166690304-hdloI9h9Vw27OZraElbtWL9GF6XPBm";
    this.ACCESS_TOKEN_KEY_SECRET = "chgUBxGwAU3EI2njwyQXtXZZFw2tX7xAMdelA2zJuFBR3";
    this.setReply();
  }

});
// CONCATENATED MODULE: ./components/AnswerWaitReply.vue?vue&type=script&lang=js&
 /* harmony default export */ var components_AnswerWaitReplyvue_type_script_lang_js_ = (AnswerWaitReplyvue_type_script_lang_js_); 
// EXTERNAL MODULE: ./node_modules/vue-loader/lib/runtime/componentNormalizer.js
var componentNormalizer = __webpack_require__(2);

// CONCATENATED MODULE: ./components/AnswerWaitReply.vue



function injectStyles (context) {
  
  var style0 = __webpack_require__(34)
if (style0.__inject__) style0.__inject__(context)

}

/* normalize component */

var component = Object(componentNormalizer["a" /* default */])(
  components_AnswerWaitReplyvue_type_script_lang_js_,
  render,
  staticRenderFns,
  false,
  injectStyles,
  "24fe3ecd",
  "1a790e17"
  
)

/* harmony default export */ var AnswerWaitReply = __webpack_exports__["default"] = (component.exports);

/* nuxt-component-imports */
installComponents(component, {SharedSendSentence: __webpack_require__(29).default})


/***/ }),
/* 40 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_vue_style_loader_index_js_ref_3_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_3_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_3_oneOf_1_2_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_0_lang_css___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(36);
/* harmony import */ var _node_modules_vue_style_loader_index_js_ref_3_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_3_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_3_oneOf_1_2_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_0_lang_css___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_vue_style_loader_index_js_ref_3_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_3_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_3_oneOf_1_2_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_0_lang_css___WEBPACK_IMPORTED_MODULE_0__);
/* harmony reexport (unknown) */ for(var __WEBPACK_IMPORT_KEY__ in _node_modules_vue_style_loader_index_js_ref_3_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_3_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_3_oneOf_1_2_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_0_lang_css___WEBPACK_IMPORTED_MODULE_0__) if(["default"].indexOf(__WEBPACK_IMPORT_KEY__) < 0) (function(key) { __webpack_require__.d(__webpack_exports__, key, function() { return _node_modules_vue_style_loader_index_js_ref_3_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_3_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_3_oneOf_1_2_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_0_lang_css___WEBPACK_IMPORTED_MODULE_0__[key]; }) }(__WEBPACK_IMPORT_KEY__));


/***/ }),
/* 41 */
/***/ (function(module, exports, __webpack_require__) {

// Imports
var ___CSS_LOADER_API_IMPORT___ = __webpack_require__(8);
var ___CSS_LOADER_GET_URL_IMPORT___ = __webpack_require__(42);
var ___CSS_LOADER_URL_IMPORT_0___ = __webpack_require__(43);
var ___CSS_LOADER_EXPORT___ = ___CSS_LOADER_API_IMPORT___(false);
var ___CSS_LOADER_URL_REPLACEMENT_0___ = ___CSS_LOADER_GET_URL_IMPORT___(___CSS_LOADER_URL_IMPORT_0___);
// Module
___CSS_LOADER_EXPORT___.push([module.i, "@font-face{font-family:\"azuki\";src:url(" + ___CSS_LOADER_URL_REPLACEMENT_0___ + ") format(\"truetype\")}*{font-family:azuki;margin:0;padding:0}", ""]);
// Exports
module.exports = ___CSS_LOADER_EXPORT___;


/***/ }),
/* 42 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = function (url, options) {
  if (!options) {
    // eslint-disable-next-line no-param-reassign
    options = {};
  } // eslint-disable-next-line no-underscore-dangle, no-param-reassign


  url = url && url.__esModule ? url.default : url;

  if (typeof url !== 'string') {
    return url;
  } // If url is already wrapped in quotes, remove them


  if (/^['"].*['"]$/.test(url)) {
    // eslint-disable-next-line no-param-reassign
    url = url.slice(1, -1);
  }

  if (options.hash) {
    // eslint-disable-next-line no-param-reassign
    url += options.hash;
  } // Should url be wrapped?
  // See https://drafts.csswg.org/css-values-3/#urls


  if (/["'() \t\n]/.test(url) || options.needQuotes) {
    return "\"".concat(url.replace(/"/g, '\\"').replace(/\n/g, '\\n'), "\"");
  }

  return url;
};

/***/ }),
/* 43 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__.p + "fonts/azuki.8e71322.ttf";

/***/ }),
/* 44 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_1_id_809a8cd8_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(37);
/* harmony import */ var _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_1_id_809a8cd8_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_1_id_809a8cd8_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__);
/* harmony reexport (unknown) */ for(var __WEBPACK_IMPORT_KEY__ in _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_1_id_809a8cd8_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__) if(["default"].indexOf(__WEBPACK_IMPORT_KEY__) < 0) (function(key) { __webpack_require__.d(__webpack_exports__, key, function() { return _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_index_vue_vue_type_style_index_1_id_809a8cd8_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__[key]; }) }(__WEBPACK_IMPORT_KEY__));


/***/ }),
/* 45 */
/***/ (function(module, exports, __webpack_require__) {

// Imports
var ___CSS_LOADER_API_IMPORT___ = __webpack_require__(8);
var ___CSS_LOADER_EXPORT___ = ___CSS_LOADER_API_IMPORT___(false);
// Module
___CSS_LOADER_EXPORT___.push([module.i, "#app header[data-v-809a8cd8]{width:100%;height:70px;background-color:#fff;position:fixed;top:0;display:flex;justify-content:space-between;align-items:center;box-shadow:0 0 10px 5px rgba(0,0,0,.2);z-index:1000}#app header h1[data-v-809a8cd8]{cursor:pointer}#app header .nuxt-link[data-v-809a8cd8]{width:20%;height:100%;background-color:rgba(0,0,0,.1);display:flex;align-items:center;justify-content:center;color:#333;text-decoration:none;transition:.5s}#app header .nuxt-link[data-v-809a8cd8]:hover{background-color:#303030;color:#fff}#app header button[data-v-809a8cd8]{width:20%;height:100%;background-color:rgba(0,0,0,.1);display:flex;align-items:center;justify-content:center;color:#333;text-decoration:none;transition:.5s;border:none;cursor:pointer}#app header button[data-v-809a8cd8]:hover{background-color:#303030;color:#fff}#app .answer-wait-post[data-v-809a8cd8],#app .answer-wait-reply[data-v-809a8cd8]{margin-top:90px}@media (max-width:520px){#app header[data-v-809a8cd8]{height:60px}#app header h1[data-v-809a8cd8]{display:none}#app header .nuxt-link[data-v-809a8cd8]{width:50%}#app header button[data-v-809a8cd8]{border-left:1px solid #303030;width:50%}}", ""]);
// Exports
module.exports = ___CSS_LOADER_EXPORT___;


/***/ }),
/* 46 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// CONCATENATED MODULE: ./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/@nuxt/components/dist/loader.js??ref--0-0!./node_modules/vue-loader/lib??vue-loader-options!./pages/index.vue?vue&type=template&id=809a8cd8&scoped=true&
var render = function () {var _vm=this;var _h=_vm.$createElement;var _c=_vm._self._c||_h;return _c('div',{attrs:{"id":"app"}},[_vm._ssrNode("<header data-v-809a8cd8>","</header>",[_vm._ssrNode("<button data-v-809a8cd8>質問箱を見に行く</button> "),_c('h1',{directives:[{name:"scroll-to",rawName:"v-scroll-to",value:({
        element: '#app',
        offset: -200,
        duration: 500,
      }),expression:"{\n        element: '#app',\n        offset: -200,\n        duration: 500,\n      }"}]},[_vm._ssrNode("\n      質問箱(管理者版)\n    ")]),_vm._ssrNode(" <button data-v-809a8cd8>画面切り替え</button>")],2),_vm._ssrNode(" "),_c('AnswerWaitPost',{directives:[{name:"show",rawName:"v-show",value:(_vm.showPost),expression:"showPost"}],staticClass:"answer-wait-post"}),_vm._ssrNode(" "),_c('AnswerWaitReply',{directives:[{name:"show",rawName:"v-show",value:(_vm.showReply),expression:"showReply"}],staticClass:"answer-wait-reply"})],2)}
var staticRenderFns = []


// CONCATENATED MODULE: ./pages/index.vue?vue&type=template&id=809a8cd8&scoped=true&

// CONCATENATED MODULE: ./node_modules/babel-loader/lib??ref--2-0!./node_modules/@nuxt/components/dist/loader.js??ref--0-0!./node_modules/vue-loader/lib??vue-loader-options!./pages/index.vue?vue&type=script&lang=js&
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
/* harmony default export */ var lib_vue_loader_options_pagesvue_type_script_lang_js_ = ({
  data() {
    return {
      showPost: true,
      showReply: false
    };
  },

  methods: {
    changePage() {
      this.showPost = !this.showPost;
      this.showReply = !this.showReply;
    },

    toQBox() {
      const url = "https://unique-donut-e9d728.netlify.app/";
      window.open(url, "_blank");
    }

  }
});
// CONCATENATED MODULE: ./pages/index.vue?vue&type=script&lang=js&
 /* harmony default export */ var pagesvue_type_script_lang_js_ = (lib_vue_loader_options_pagesvue_type_script_lang_js_); 
// EXTERNAL MODULE: ./node_modules/vue-loader/lib/runtime/componentNormalizer.js
var componentNormalizer = __webpack_require__(2);

// CONCATENATED MODULE: ./pages/index.vue



function injectStyles (context) {
  
  var style0 = __webpack_require__(40)
if (style0.__inject__) style0.__inject__(context)
var style1 = __webpack_require__(44)
if (style1.__inject__) style1.__inject__(context)

}

/* normalize component */

var component = Object(componentNormalizer["a" /* default */])(
  pagesvue_type_script_lang_js_,
  render,
  staticRenderFns,
  false,
  injectStyles,
  "809a8cd8",
  "77b340be"
  
)

/* harmony default export */ var pages = __webpack_exports__["default"] = (component.exports);

/* nuxt-component-imports */
installComponents(component, {AnswerWaitPost: __webpack_require__(38).default,AnswerWaitReply: __webpack_require__(39).default})


/***/ })
]);;
//# sourceMappingURL=index.js.map