(window.webpackJsonp=window.webpackJsonp||[]).push([[11],{301:function(e,t,r){var content=r(338);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[e.i,content,""]]),content.locals&&(e.exports=content.locals);(0,r(107).default)("5cdedf14",content,!0,{sourceMap:!1})},337:function(e,t,r){"use strict";r(301)},338:function(e,t,r){var n=r(106)(!1);n.push([e.i,".send-sentence[data-v-1429837f]{margin:70px auto 0;width:60%;transition:0s}h2[data-v-1429837f]{margin:30px 0;font-size:2.2em}ul[data-v-1429837f]{width:60%;margin:0 auto}ul li[data-v-1429837f]{display:flex;flex-direction:column;align-items:center;margin-bottom:30px;padding:5%;box-shadow:0 0 5px 5px rgba(0,0,0,.1)}ul li canvas[data-v-1429837f]{width:100%;border-radius:10px}ul li p[data-v-1429837f]{white-space:pre-line;word-wrap:break-word}ul li .primary-post[data-v-1429837f]{width:80%;text-align:center;margin:5px auto}ul li .primary-post .card-button[data-v-1429837f]{transition:.5s;cursor:pointer}ul li .primary-post .card-button[data-v-1429837f]:hover{opacity:.7}ul li .primary-post .answer[data-v-1429837f]{width:80%;margin:10px auto}ul li .primary-post .created-at[data-v-1429837f]{width:100px;padding:5px 10px;margin:10px;border-radius:5px;border:2px solid rgba(67,134,135,.7);background-color:#75b8b9;color:#fff}ul li .secondary-post[data-v-1429837f]{width:60%;text-align:center;margin:5px auto}ul li .secondary-post p[data-v-1429837f]{width:80%;margin:10px auto}.spinner[data-v-1429837f]{-webkit-animation:spinner-data-v-1429837f 1s ease infinite;animation:spinner-data-v-1429837f 1s ease infinite}@-webkit-keyframes spinner-data-v-1429837f{0%{opacity:1}50%{opacity:0}to{opacity:1}}@keyframes spinner-data-v-1429837f{0%{opacity:1}50%{opacity:0}to{opacity:1}}.no-more[data-v-1429837f],.no-results[data-v-1429837f],.spinner[data-v-1429837f]{margin:30px auto}@media (max-width:1024px){ul[data-v-1429837f]{width:100%}}@media (max-width:520px){.send-sentence[data-v-1429837f]{width:100%;margin:0!important}ul[data-v-1429837f]{width:100%}ul h2[data-v-1429837f]{font-size:1.6em;margin:0 10px 10px}ul li[data-v-1429837f]{width:100%;padding:20px 0}ul li .primary-post[data-v-1429837f]{width:90%}ul li .secondary-post[data-v-1429837f]{width:75%}}",""]),e.exports=n},395:function(e,t,r){var content=r(490);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[e.i,content,""]]),content.locals&&(e.exports=content.locals);(0,r(107).default)("1b7833da",content,!0,{sourceMap:!1})},396:function(e,t,r){var content=r(492);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[e.i,content,""]]),content.locals&&(e.exports=content.locals);(0,r(107).default)("42244646",content,!0,{sourceMap:!1})},400:function(e,t,r){"use strict";r.r(t);r(41),r(13),r(35),r(42),r(23),r(29),r(43),r(44);var n=r(8),o=(r(51),r(30),r(31),r(73),r(267)),d=r(108),c=r(281),l=r.n(c);function f(e,t){var r="undefined"!=typeof Symbol&&e[Symbol.iterator]||e["@@iterator"];if(!r){if(Array.isArray(e)||(r=function(e,t){if(!e)return;if("string"==typeof e)return h(e,t);var r=Object.prototype.toString.call(e).slice(8,-1);"Object"===r&&e.constructor&&(r=e.constructor.name);if("Map"===r||"Set"===r)return Array.from(e);if("Arguments"===r||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(r))return h(e,t)}(e))||t&&e&&"number"==typeof e.length){r&&(e=r);var i=0,n=function(){};return{s:n,n:function(){return i>=e.length?{done:!0}:{done:!1,value:e[i++]}},e:function(e){throw e},f:n}}throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}var o,d=!0,c=!1;return{s:function(){r=r.call(e)},n:function(){var e=r.next();return d=e.done,e},e:function(e){c=!0,o=e},f:function(){try{d||null==r.return||r.return()}finally{if(c)throw o}}}}function h(e,t){(null==t||t>e.length)&&(t=e.length);for(var i=0,r=new Array(t);i<t;i++)r[i]=e[i];return r}var v={components:{SendSentence:o.default,InfiniteLoading:l.a},data:function(){return{MICROCMS_KEY:"",posts:[],modeQuestion:"question",modeReply:"reply",postCount:0}},methods:{transition:function(e){this.$router.push({path:e})},setReply:function(){var e=this;return Object(n.a)(regeneratorRuntime.mark((function t(){var r,n,o;return regeneratorRuntime.wrap((function(t){for(;;)switch(t.prev=t.next){case 0:if(!e.posts){t.next=17;break}r=f(e.posts),t.prev=2,o=regeneratorRuntime.mark((function t(){var r;return regeneratorRuntime.wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return r=n.value,t.next=3,e.$axios.$get("https://q-box.microcms.io/api/v1/q_box_replies?filters=replyFor[equals]"+r.id+"[and]replyAnswer[exists]&orders=createdAt",{headers:{"X-MICROCMS-API-KEY":e.MICROCMS_KEY}}).then((function(t){d.a.generateImage(document,t.contents,"replySentence",""),e.$set(r,"replies",t.contents),d.a.modifyUrlInPost(r.replies,"replyAnswer")})).catch((function(e){console.log(e)}));case 3:case"end":return t.stop()}}),t)})),r.s();case 5:if((n=r.n()).done){t.next=9;break}return t.delegateYield(o(),"t0",7);case 7:t.next=5;break;case 9:t.next=14;break;case 11:t.prev=11,t.t1=t.catch(2),r.e(t.t1);case 14:return t.prev=14,r.f(),t.finish(14);case 17:case"end":return t.stop()}}),t,null,[[2,11,14,17]])})))()},loadNewPost:function(e){var t=this;return Object(n.a)(regeneratorRuntime.mark((function r(){return regeneratorRuntime.wrap((function(r){for(;;)switch(r.prev=r.next){case 0:return 10,r.next=3,t.$axios.$get("https://q-box.microcms.io/api/v1/q_box_posts?filters=answer[exists]&limit=10&offset="+t.postCount,{headers:{"X-MICROCMS-API-KEY":t.MICROCMS_KEY}}).then((function(r){t.postCount<r.totalCount?(d.a.modifyUrlInPost(r.contents,"answer"),t.posts=t.posts.concat(r.contents),d.a.generateImage(document,r.contents,"question",""),t.setReply(),t.postCount+=r.contents.length,e.loaded()):e.complete()})).catch((function(t){e.error(),alert("通信に失敗しました。："+t),console.log(t)}));case 3:case"end":return r.stop()}}),r)})))()}},created:function(){var e=this;return Object(n.a)(regeneratorRuntime.mark((function t(){return regeneratorRuntime.wrap((function(t){for(;;)switch(t.prev=t.next){case 0:e.MICROCMS_KEY="f999ee3a5b064d859ee8072912dd0265ab9f";case 1:case"end":return t.stop()}}),t)})))()}},m=(r(337),r(52)),component=Object(m.a)(v,(function(){var e=this,t=e.$createElement,r=e._self._c||t;return r("div",{staticClass:"app"},[r("SendSentence",{staticClass:"send-sentence",attrs:{mode:e.modeQuestion,show:!0,MICROCMS_KEY:e.MICROCMS_KEY}}),e._v(" "),r("ul",[r("h2",[e._v("最新の質問")]),e._v(" "),r("p",{directives:[{name:"show",rawName:"v-show",value:!e.posts[0],expression:"!posts[0]"}]},[e._v("質問はありません")]),e._v(" "),e._l(e.posts,(function(t){return r("li",{key:t.id},[r("div",{staticClass:"primary-post"},[r("p",{staticClass:"created-at"},[e._v(e._s(t.createdAt.substr(0,10)))]),e._v(" "),r("div",{staticClass:"card-button",on:{click:function(r){return e.transition(t.id)}}},[r("canvas",{attrs:{id:t.id}})]),e._v(" "),r("p",{staticClass:"answer",domProps:{innerHTML:e._s(t.answer)}})]),e._v(" "),e._l(t.replies,(function(t){return r("div",{key:t.id,staticClass:"secondary-post"},[r("canvas",{attrs:{id:t.id}}),e._v(" "),r("p",{domProps:{innerHTML:e._s(t.replyAnswer)}})])})),e._v(" "),r("SendSentence",{attrs:{mode:e.modeReply,contentId:t.id,show:!0,MICROCMS_KEY:e.MICROCMS_KEY}})],2)}))],2),e._v(" "),r("infinite-loading",{on:{infinite:e.loadNewPost}},[r("div",{staticClass:"spinner",attrs:{slot:"spinner"},slot:"spinner"},[e._v("読み込んでいます...")]),e._v(" "),r("div",{staticClass:"no-more",attrs:{slot:"no-more"},slot:"no-more"},[e._v("条件に合致した質問は以上です。")]),e._v(" "),r("div",{staticClass:"no-results",attrs:{slot:"no-results"},slot:"no-results"},[e._v("条件に合致した質問は見つかりませんでした。")]),e._v(" "),r("div",{staticClass:"no-results",attrs:{slot:"error"},slot:"error"},[e._v("エラーが発生しました。")])])],1)}),[],!1,null,"1429837f",null);t.default=component.exports},489:function(e,t,r){"use strict";r(395)},490:function(e,t,r){var n=r(106),o=r(300),d=r(336),c=n(!1),l=o(d);c.push([e.i,'@font-face{font-family:"azuki";src:url('+l+') format("truetype")}*{font-family:azuki;margin:0;padding:0}',""]),e.exports=c},491:function(e,t,r){"use strict";r(396)},492:function(e,t,r){var n=r(106)(!1);n.push([e.i,"header[data-v-7ee11f34]{width:100%;height:70px;position:fixed;top:0;display:flex;justify-content:space-between;align-items:center;box-shadow:0 0 10px 5px rgba(0,0,0,.2);background-color:#fff;z-index:1000}header h1[data-v-7ee11f34]{z-index:100;cursor:pointer}header .nuxt-link[data-v-7ee11f34]{z-index:100;width:20%;height:100%;background-color:rgba(0,0,0,.1);display:flex;align-items:center;justify-content:center;color:#333;text-decoration:none;text-align:center;transition:.5s}header .nuxt-link[data-v-7ee11f34]:hover{background-color:#303030;color:#fff}header input[data-v-7ee11f34]{z-index:100;padding-left:10px;width:calc(20% - 10px);height:100%;background-color:rgba(0,0,0,.1);border:none;outline:none;font-size:1.2em;transition:.5s}header input[data-v-7ee11f34]:focus{background-color:#303030;color:#fff}header .often-search-word-box[data-v-7ee11f34]{transform-origin:center center;position:absolute;z-index:0;background-color:rgba(0,0,0,.8);top:100%;left:0;width:100%;max-height:200px;padding:10px;overflow:scroll;box-shadow:0 10px 10px 1px rgba(0,0,0,.2)}header .often-search-word-box h3[data-v-7ee11f34]{margin:10px;color:#fff}header .often-search-word-box ul[data-v-7ee11f34]{display:flex;flex-wrap:wrap;width:100%}header .often-search-word-box ul li[data-v-7ee11f34]{list-style:none;width:11%;height:40px;display:flex;justify-content:center;align-items:center;border:1px solid #fff;color:#fff;border-radius:5px;margin:0 calc(.75% - 2.25px) 10px;cursor:pointer;transition:.5s;overflow:hidden}header .often-search-word-box ul li[data-v-7ee11f34]:hover{background-color:#303030;color:#fff}.filtered-post[data-v-7ee11f34],.new-post[data-v-7ee11f34]{margin-top:70px}.v-enter[data-v-7ee11f34]{opacity:0;transform:scale(90%)}.v-enter-to[data-v-7ee11f34]{opacity:1;transform:scale(100%)}.v-enter-active[data-v-7ee11f34]{transition:.2s}.v-leave[data-v-7ee11f34]{opacity:1;transform:scale(100%)}.v-leave-to[data-v-7ee11f34]{opacity:0;transform:scale(90%)}.v-leave-active[data-v-7ee11f34]{transition:.2s}.chevron-up[data-v-7ee11f34]{display:none}@media (max-width:520px){header[data-v-7ee11f34]{height:60px}header h1[data-v-7ee11f34]{display:none}header .nuxt-link[data-v-7ee11f34]{width:50%}header input[data-v-7ee11f34]{border-left:1px solid #303030;width:50%;padding-left:0;text-align:center}header .often-search-word-box[data-v-7ee11f34]{padding:10px 5px 0}header .often-search-word-box ul li[data-v-7ee11f34]{width:30%;margin:0 calc(1.66667% - 2.66667px) 10px}.chevron-up[data-v-7ee11f34]{position:fixed;bottom:40px;right:30px;width:70px;height:70px;display:flex;justify-content:center;align-items:center;border-radius:50%;border:2px solid #fff;background-color:rgba(0,0,0,.6);color:#fff;font-size:2.2em}}",""]),e.exports=n},501:function(e,t,r){"use strict";r.r(t);var n=r(488),o={data:function(){return{faChevronUp:n.a,showNewPost:!0,showFilteredPost:!1,qWord:"",showSearchWord:!1,searchWords:["TOEFL","サークル","般教","一般教養１","バイト"]}},methods:{searchPost:function(e){e&&(this.$refs.FilteredPost.getPost(e),this.changeShowMode())},changeShowMode:function(){this.showNewPost=!1,this.showFilteredPost=!0},toggleSearchWord:function(e){this.showSearchWord=e},inputSearchWord:function(e){this.searchPost(e),this.toggleSearchWord(!1)}},mounted:function(){console.log(this.$refs.FilteredPost)}},d=(r(489),r(491),r(52)),component=Object(d.a)(o,(function(){var e=this,t=e.$createElement,r=e._self._c||t;return r("div",{attrs:{id:"app"}},[r("header",[r("nuxt-link",{staticClass:"nuxt-link",attrs:{to:"/answer"}},[e._v("管理者画面に移動する")]),e._v(" "),r("h1",{directives:[{name:"scroll-to",rawName:"v-scroll-to",value:{element:"#app",offset:-200,duration:500},expression:"{\n      element: '#app',\n      offset: -200,\n      duration: 500\n    }"}]},[e._v("お手サーの質問箱")]),e._v(" "),r("input",{directives:[{name:"model",rawName:"v-model",value:e.qWord,expression:"qWord"}],attrs:{id:"search-input",type:"text",autocomplete:"off",placeholder:"語句で検索"},domProps:{value:e.qWord},on:{keyup:function(t){return!t.type.indexOf("key")&&e._k(t.keyCode,"enter",13,t.key,"Enter")?null:e.searchPost(e.qWord)},click:function(t){return e.toggleSearchWord(!e.showSearchWord)},input:function(t){t.target.composing||(e.qWord=t.target.value)}}}),e._v(" "),r("transition",[r("div",{directives:[{name:"show",rawName:"v-show",value:e.showSearchWord&&!e.qWord,expression:"showSearchWord && !qWord"}],staticClass:"often-search-word-box"},[r("h3",[e._v("良く検索されるワード")]),e._v(" "),r("ul",e._l(this.searchWords,(function(t){return r("li",{key:t,on:{click:function(r){return e.inputSearchWord(t)}}},[e._v("\n            "+e._s(t)+"\n          ")])})),0)])])],1),e._v(" "),r("div",{on:{click:function(t){return e.toggleSearchWord(!1)}}},[r("NewPost",{directives:[{name:"show",rawName:"v-show",value:e.showNewPost,expression:"showNewPost"}],staticClass:"new-post"}),e._v(" "),r("FilteredPost",{directives:[{name:"show",rawName:"v-show",value:e.showFilteredPost,expression:"showFilteredPost"}],ref:"FilteredPost",staticClass:"filtered-post"}),e._v(" "),r("div",{directives:[{name:"scroll-to",rawName:"v-scroll-to",value:{element:"#app",offset:-200,duration:500},expression:"{\n      element: '#app',\n      offset: -200,\n      duration: 500\n      }"}],staticClass:"chevron-up"},[r("fa",{attrs:{icon:e.faChevronUp}})],1)],1)])}),[],!1,null,"7ee11f34",null);t.default=component.exports;installComponents(component,{NewPost:r(400).default,FilteredPost:r(401).default})}}]);