exports.ids = [3];
exports.modules = {

/***/ 25:
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

/***/ 26:
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

/***/ 27:
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SendSentence_vue_vue_type_style_index_0_id_218f8c1e_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(25);
/* harmony import */ var _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SendSentence_vue_vue_type_style_index_0_id_218f8c1e_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SendSentence_vue_vue_type_style_index_0_id_218f8c1e_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__);
/* harmony reexport (unknown) */ for(var __WEBPACK_IMPORT_KEY__ in _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SendSentence_vue_vue_type_style_index_0_id_218f8c1e_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__) if(["default"].indexOf(__WEBPACK_IMPORT_KEY__) < 0) (function(key) { __webpack_require__.d(__webpack_exports__, key, function() { return _node_modules_vue_style_loader_index_js_ref_7_oneOf_1_0_node_modules_css_loader_dist_cjs_js_ref_7_oneOf_1_1_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_postcss_loader_src_index_js_ref_7_oneOf_1_2_node_modules_sass_loader_dist_cjs_js_ref_7_oneOf_1_3_node_modules_nuxt_components_dist_loader_js_ref_0_0_node_modules_vue_loader_lib_index_js_vue_loader_options_SendSentence_vue_vue_type_style_index_0_id_218f8c1e_scoped_true_lang_scss___WEBPACK_IMPORTED_MODULE_0__[key]; }) }(__WEBPACK_IMPORT_KEY__));


/***/ }),

/***/ 28:
/***/ (function(module, exports, __webpack_require__) {

// Imports
var ___CSS_LOADER_API_IMPORT___ = __webpack_require__(8);
var ___CSS_LOADER_EXPORT___ = ___CSS_LOADER_API_IMPORT___(false);
// Module
___CSS_LOADER_EXPORT___.push([module.i, ".sentence-box[data-v-218f8c1e]{width:calc(100% - 40px);height:150px;display:flex;flex-direction:column;align-items:center;transition:.5s;padding-top:20px;overflow:hidden}.sentence-box h3[data-v-218f8c1e]{margin:10px auto}.sentence-box textarea[data-v-218f8c1e]{resize:none;width:calc(80% - 40px);height:30px;padding:20px;outline:none;border-color:rgba(0,0,0,.15);border-width:2px;border-radius:10px}.sentence-box button[data-v-218f8c1e]{width:80px;height:30px;margin-top:10px;border:1px solid rgba(0,0,0,.3);border-radius:5px;background:none;transition:.5s;cursor:pointer}.sentence-box button[data-v-218f8c1e]:hover{background-color:#77d;border:1px solid #0000c8;color:#fff}.held .button[data-v-218f8c1e]{color:#fff;border:1px solid #fff}.boxHeightInPosts[data-v-218f8c1e]{height:114px}.v-enter[data-v-218f8c1e]{opacity:0;height:0;padding-top:0}.v-enter-to[data-v-218f8c1e]{opacity:1;height:150px;padding-top:20px}.v-enter-active[data-v-218f8c1e]{transition:.5s}.v-leave[data-v-218f8c1e]{opacity:1;padding-top:20px}.v-leave-to[data-v-218f8c1e]{opacity:0;height:0;padding-top:0}.v-leave-active[data-v-218f8c1e]{transition:.5s}@media (max-width:520px){.sentence-box[data-v-218f8c1e]{width:100%;padding-top:10px}.sentence-box h3[data-v-218f8c1e]{font-size:1em}.sentence-box textarea[data-v-218f8c1e]{width:calc(90% - 40px);padding:10px}.boxHeightInPosts[data-v-218f8c1e]{height:94px}.v-enter[data-v-218f8c1e]{opacity:0;height:0;padding-top:0}.v-enter-to[data-v-218f8c1e]{opacity:1;padding-top:10px;height:150px}.v-enter-active[data-v-218f8c1e]{transition:.5s}.v-leave[data-v-218f8c1e]{opacity:1;padding-top:10px;height:150px}.v-leave-to[data-v-218f8c1e]{opacity:0;height:0;padding-top:0}.v-leave-active[data-v-218f8c1e]{transition:opacity .1s,padding-top .5s,height .5s}}", ""]);
// Exports
module.exports = ___CSS_LOADER_EXPORT___;


/***/ }),

/***/ 29:
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

/***/ })

};;
//# sourceMappingURL=shared-send-sentence.js.map