(window.webpackJsonp=window.webpackJsonp||[]).push([[6],{273:function(t,e,o){var content=o(292);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(133).default)("797b4eda",content,!0,{sourceMap:!1})},287:function(t,e,o){"use strict";var n=o(6),r=o(3),d=o(60),l=o(22),c=o(33),h=o(12),f=o(4),v=o(188),x=o(134),w=o(288),_=o(289),E=o(71),m=o(290),C=[],S=r(C.sort),y=r(C.push),K=f((function(){C.sort(void 0)})),R=f((function(){C.sort(null)})),M=x("sort"),k=!f((function(){if(E)return E<70;if(!(w&&w>3)){if(_)return!0;if(m)return m<603;var code,t,e,o,n="";for(code=65;code<76;code++){switch(t=String.fromCharCode(code),code){case 66:case 69:case 70:case 72:e=3;break;case 68:case 71:e=4;break;default:e=2}for(o=0;o<47;o++)C.push({k:t+o,v:e})}for(C.sort((function(a,b){return b.v-a.v})),o=0;o<C.length;o++)t=C[o].k.charAt(0),n.charAt(n.length-1)!==t&&(n+=t);return"DGBEFHACIJK"!==n}}));n({target:"Array",proto:!0,forced:K||!R||!M||!k},{sort:function(t){void 0!==t&&d(t);var e=l(this);if(k)return void 0===t?S(e):S(e,t);var o,n,r=[],f=c(e);for(n=0;n<f;n++)n in e&&y(r,e[n]);for(v(r,function(t){return function(e,o){return void 0===o?-1:void 0===e?1:void 0!==t?+t(e,o)||0:h(e)>h(o)?1:-1}}(t)),o=r.length,n=0;n<o;)e[n]=r[n++];for(;n<f;)delete e[n++];return e}})},288:function(t,e,o){var n=o(59).match(/firefox\/(\d+)/i);t.exports=!!n&&+n[1]},289:function(t,e,o){var n=o(59);t.exports=/MSIE|Trident/.test(n)},290:function(t,e,o){var n=o(59).match(/AppleWebKit\/(\d+)\./);t.exports=!!n&&+n[1]},291:function(t,e,o){"use strict";o(273)},292:function(t,e,o){var n=o(132)(!1);n.push([t.i,"header[data-v-29b0eea8]{width:100%;height:70px;display:flex;justify-content:center;align-items:center}ul[data-v-29b0eea8]{width:80%;margin:0 auto}ul>div[data-v-29b0eea8]{display:flex;margin:10px 0}ul h2[data-v-29b0eea8]{font-size:2.2em}ul li[data-v-29b0eea8]{flex-direction:column;list-style:none;box-shadow:0 0 5px 5px rgba(0,0,0,.1);padding:20px;margin:20px 0;word-wrap:break-word}ul li[data-v-29b0eea8],ul li .box[data-v-29b0eea8]{display:flex;align-items:center}ul li .box[data-v-29b0eea8]{width:100%;justify-content:space-between}ul li .box h3[data-v-29b0eea8]{width:70%;text-align:center;white-space:pre-wrap}ul li .box button[data-v-29b0eea8],ul li .box div button[data-v-29b0eea8]{width:50px;height:30px;border:1px solid rgba(0,0,0,.3);border-radius:5px;background:none;transition:.5s;cursor:pointer}ul li .box button[data-v-29b0eea8]:hover,ul li .box div button[data-v-29b0eea8]:hover{background-color:#d77;border:1px solid #c80000;color:#fff}ul li .box .toggle-button[data-v-29b0eea8]{width:100px}ul li .box .toggle-button[data-v-29b0eea8]:hover{background-color:#303030;border-color:#303030}ul .held[data-v-29b0eea8]{background-color:#333;color:#fff}ul .held .box div button[data-v-29b0eea8],ul .held div .toggle-button[data-v-29b0eea8]{color:#fff;border:1px solid #fff}ul .held div .toggle-button[data-v-29b0eea8]:hover{background-color:#fff;border:1px solid #fff;color:#303030}.flip-list-move[data-v-29b0eea8]{transition:transform .5s}@media (max-width:520px){ul[data-v-29b0eea8]{width:100%}ul div h2[data-v-29b0eea8]{font-size:1.6em;margin-left:10px}ul li[data-v-29b0eea8]{padding:10px;margin:10px 0}ul li .box h3[data-v-29b0eea8]{width:auto;font-size:1em;max-width:calc(100% - 120px)}ul li .box div[data-v-29b0eea8]{width:50px}ul li .box div button[data-v-29b0eea8]{margin:5px 0}ul li .box .toggle-button[data-v-29b0eea8]{width:50px;height:70px}}",""]),t.exports=n},328:function(t,e,o){var content=o(385);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(133).default)("1b7833da",content,!0,{sourceMap:!1})},329:function(t,e,o){var content=o(389);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(133).default)("943f4c24",content,!0,{sourceMap:!1})},383:function(t,e,o){"use strict";o.r(e);var n=o(8),r=(o(287),o(50),o(102)),d={data:function(){return{posts:[],modeAnswer:"answer",heldOnly:!1,MICROCMS_KEY:"",CONSUMER_KEY:"",CONSUMER_KEY_SECRET:"",ACCESS_TOKEN_KEY:"",ACCESS_TOKEN_KEY_SECRET:""}},methods:{showSendSentence:function(t){this.$refs[t][0].toggle()},getPosts:function(){var t=this;return Object(n.a)(regeneratorRuntime.mark((function e(){return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,t.$axios.$get("https://q-box.microcms.io/api/v1/q_box_posts?filters=answer[not_exists]&orders=createdAt",{headers:{"X-MICROCMS-API-KEY":t.MICROCMS_KEY}}).then((function(e){t.$set(t,"posts",e.contents)})).catch((function(t){alert("通信に失敗しました。："+t),console.log(t)}));case 2:case"end":return e.stop()}}),e)})))()},deletePost:function(t){r.a.deletePost(this,t,"q_box_posts",this.MICROCMS_KEY)},holdPost:function(t,e){r.a.holdPost(this,t,"q_box_posts",this.MICROCMS_KEY,e)},held:function(){this.heldOnly?this.posts.sort((function(t,e){return t.createdAt>e.createdAt?0:-1})):this.posts.sort((function(t,e){return t.held===e.held?0:t.held?-1:1})),this.heldOnly=!this.heldOnly}},mounted:function(){var t=this;return Object(n.a)(regeneratorRuntime.mark((function e(){return regeneratorRuntime.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:t.MICROCMS_KEY="f999ee3a5b064d859ee8072912dd0265ab9f",t.CONSUMER_KEY="Kn7JSGK3ebklzfZKsAgq8A6BB",t.CONSUMER_KEY_SECRET="Vsdsq0vosePrRgLbgVAMjco3Na4lFVQ8QiPUP3pwBp8gQG3lMe",t.ACCESS_TOKEN_KEY="1494570525166690304-hdloI9h9Vw27OZraElbtWL9GF6XPBm",t.ACCESS_TOKEN_KEY_SECRET="chgUBxGwAU3EI2njwyQXtXZZFw2tX7xAMdelA2zJuFBR3",t.getPosts();case 6:case"end":return e.stop()}}),e)})))()}},l=(o(291),o(51)),component=Object(l.a)(d,(function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("ul",[o("div",[o("h2",[t._v("未回答の質問(古い順)")]),t._v(" "),o("button",{on:{click:t.held}},[t._v("保留のみ表示")])]),t._v(" "),o("p",{directives:[{name:"show",rawName:"v-show",value:!t.posts[0],expression:"!posts[0]"}]},[t._v("質問はありません")]),t._v(" "),o("transition-group",{attrs:{name:"flip-list"}},t._l(t.posts,(function(e){return o("li",{key:e.id,class:{held:e.held}},[o("div",{staticClass:"box"},[o("div",[o("button",{on:{click:function(o){return t.deletePost(e.id)}}},[t._v("削除")]),t._v(" "),o("button",{on:{click:function(o){return t.holdPost(e.id,e.held)}}},[t._v("保留")])]),t._v(" "),o("h3",[t._v(t._s(e.question))]),t._v(" "),o("button",{staticClass:"toggle-button",on:{click:function(o){return t.showSendSentence(e.id)}}},[t._v("\n          開閉\n        ")])]),t._v(" "),o("SharedSendSentence",{ref:e.id,refInFor:!0,staticClass:"send-sentence",attrs:{mode:t.modeAnswer,"content-id":e.id,held:e.held,show:!1,MICROCMS_KEY:t.MICROCMS_KEY,CONSUMER_KEY:t.CONSUMER_KEY,CONSUMER_KEY_SECRET:t.CONSUMER_KEY_SECRET,ACCESS_TOKEN_KEY:t.ACCESS_TOKEN_KEY,ACCESS_TOKEN_KEY_SECRET:t.ACCESS_TOKEN_KEY_SECRET},on:{"get-posts":t.getPosts}})],1)})),0)],1)}),[],!1,null,"29b0eea8",null);e.default=component.exports;installComponents(component,{SharedSendSentence:o(281).default})},384:function(t,e,o){"use strict";o(328)},385:function(t,e,o){var n=o(132),r=o(386),d=o(387),l=n(!1),c=r(d);l.push([t.i,'@font-face{font-family:"azuki";src:url('+c+') format("truetype")}*{font-family:azuki;margin:0;padding:0}',""]),t.exports=l},386:function(t,e,o){"use strict";t.exports=function(t,e){return e||(e={}),"string"!=typeof(t=t&&t.__esModule?t.default:t)?t:(/^['"].*['"]$/.test(t)&&(t=t.slice(1,-1)),e.hash&&(t+=e.hash),/["'() \t\n]/.test(t)||e.needQuotes?'"'.concat(t.replace(/"/g,'\\"').replace(/\n/g,"\\n"),'"'):t)}},387:function(t,e,o){t.exports=o.p+"fonts/azuki.8e71322.ttf"},388:function(t,e,o){"use strict";o(329)},389:function(t,e,o){var n=o(132)(!1);n.push([t.i,"#app header[data-v-809a8cd8]{width:100%;height:70px;background-color:#fff;position:fixed;top:0;display:flex;justify-content:space-between;align-items:center;box-shadow:0 0 10px 5px rgba(0,0,0,.2);z-index:1000}#app header h1[data-v-809a8cd8]{cursor:pointer}#app header .nuxt-link[data-v-809a8cd8]{width:20%;height:100%;background-color:rgba(0,0,0,.1);display:flex;align-items:center;justify-content:center;color:#333;text-decoration:none;transition:.5s}#app header .nuxt-link[data-v-809a8cd8]:hover{background-color:#303030;color:#fff}#app header button[data-v-809a8cd8]{width:20%;height:100%;background-color:rgba(0,0,0,.1);display:flex;align-items:center;justify-content:center;color:#333;text-decoration:none;transition:.5s;border:none;cursor:pointer}#app header button[data-v-809a8cd8]:hover{background-color:#303030;color:#fff}#app .answer-wait-post[data-v-809a8cd8],#app .answer-wait-reply[data-v-809a8cd8]{margin-top:90px}@media (max-width:520px){#app header[data-v-809a8cd8]{height:60px}#app header h1[data-v-809a8cd8]{display:none}#app header .nuxt-link[data-v-809a8cd8]{width:50%}#app header button[data-v-809a8cd8]{border-left:1px solid #303030;width:50%}}",""]),t.exports=n},475:function(t,e,o){"use strict";o.r(e);var n={data:function(){return{showPost:!0,showReply:!1}},methods:{changePage:function(){this.showPost=!this.showPost,this.showReply=!this.showReply},toQBox:function(){window.open("https://unique-donut-e9d728.netlify.app/","_blank")}}},r=(o(384),o(388),o(51)),component=Object(r.a)(n,(function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",{attrs:{id:"app"}},[o("header",[o("button",{on:{click:t.toQBox}},[t._v("質問箱を見に行く")]),t._v(" "),o("h1",{directives:[{name:"scroll-to",rawName:"v-scroll-to",value:{element:"#app",offset:-200,duration:500},expression:"{\n        element: '#app',\n        offset: -200,\n        duration: 500,\n      }"}]},[t._v("\n      質問箱(管理者版)\n    ")]),t._v(" "),o("button",{on:{click:t.changePage}},[t._v("画面切り替え")])]),t._v(" "),o("AnswerWaitPost",{directives:[{name:"show",rawName:"v-show",value:t.showPost,expression:"showPost"}],staticClass:"answer-wait-post"}),t._v(" "),o("AnswerWaitReply",{directives:[{name:"show",rawName:"v-show",value:t.showReply,expression:"showReply"}],staticClass:"answer-wait-reply"})],1)}),[],!1,null,"809a8cd8",null);e.default=component.exports;installComponents(component,{AnswerWaitPost:o(383).default,AnswerWaitReply:o(474).default})}}]);