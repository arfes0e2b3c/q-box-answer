(window.webpackJsonp=window.webpackJsonp||[]).push([[2],{108:function(t,e,n){"use strict";var r=n(8);n(51),n(50),n(26),n(176),n(73),n(41),n(13),n(25),n(42),n(32),n(31),n(43),n(44),n(33);function o(t,e){var n="undefined"!=typeof Symbol&&t[Symbol.iterator]||t["@@iterator"];if(!n){if(Array.isArray(t)||(n=function(t,e){if(!t)return;if("string"==typeof t)return c(t,e);var n=Object.prototype.toString.call(t).slice(8,-1);"Object"===n&&t.constructor&&(n=t.constructor.name);if("Map"===n||"Set"===n)return Array.from(t);if("Arguments"===n||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n))return c(t,e)}(t))||e&&t&&"number"==typeof t.length){n&&(t=n);var i=0,r=function(){};return{s:r,n:function(){return i>=t.length?{done:!0}:{done:!1,value:t[i++]}},e:function(t){throw t},f:r}}throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}var o,f=!0,l=!1;return{s:function(){n=n.call(t)},n:function(){var t=n.next();return f=t.done,t},e:function(t){l=!0,o=t},f:function(){try{f||null==n.return||n.return()}finally{if(l)throw o}}}}function c(t,e){(null==e||e>t.length)&&(e=t.length);for(var i=0,n=new Array(e);i<e;i++)n[i]=t[i];return n}e.a={modifyUrlInPost:function(t,e){t.map((function(t){var n=t[e].match(/((https?):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/gi);t[e]=t[e].replace(/((https?):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/gi,'<a href="'+n+'" target="_blank">こちら</a>')}))},deletePost:function(t,e,n,o){return Object(r.a)(regeneratorRuntime.mark((function r(){return regeneratorRuntime.wrap((function(r){for(;;)switch(r.prev=r.next){case 0:if(!window.confirm("削除してよろしいですか？")){r.next=3;break}return r.next=3,t.$axios.$delete("https://q-box.microcms.io/api/v1/"+n+"/"+e,{headers:{"X-MICROCMS-API-KEY":o}}).then((function(){"q_box_posts"===n?t.getPosts():"q_box_replies"===n&&t.setReply()}));case 3:case"end":return r.stop()}}),r)})))()},holdPost:function(t,e,n,o,c){return Object(r.a)(regeneratorRuntime.mark((function r(){return regeneratorRuntime.wrap((function(r){for(;;)switch(r.prev=r.next){case 0:return r.next=2,t.$axios.$patch("https://q-box.microcms.io/api/v1/"+n+"/"+e,{held:!c},{headers:{"Content-Type":"application/json","X-MICROCMS-API-KEY":o}}).catch((function(t){alert("通信に失敗しました。："+t),console.log(t)})).then((function(){"q_box_posts"===n?t.getPosts():"q_box_replies"===n&&t.setReply()}));case 2:case"end":return r.stop()}}),r)})))()},generateImage:function(t,e,r,c){var f,l=o(e);try{var h=function(){var e=f.value;(image=new Image).src=n(260),image.onload=function(){var canvas=t.getElementById(e.id+c),n=canvas.getContext("2d");canvas.width=600,canvas.height=315;var f,l=[""],line=0,h=o(e[r]);try{for(h.s();!(f=h.n()).done;){var d=f.value;(d.match(/\n/)||2*n.measureText(l[line]+d).width>.65*canvas.width)&&(l[++line]=""),l[line]+=d}}catch(t){h.e(t)}finally{h.f()}var m=1.5*n.measureText("あ").width*2;line>3&&(canvas.height=canvas.height+(line-3)*m*21/16),n.drawImage(image,0,0,canvas.width,canvas.height),n.font="20px azuki",n.fillStyle="#404040",n.textBaseline="center",n.textAlign="center";for(var i=0;i<l.length;i++)n.fillText(l[i],canvas.width/2,canvas.height/2+m*i-m*(l.length-1)/2);n.font="30px azuki",n.fillStyle="#fff",n.fillText("お手サー",canvas.width/6,canvas.height/1.058)}};for(l.s();!(f=l.n()).done;){var image;h()}}catch(t){l.e(t)}finally{l.f()}}}},137:function(t,e,n){"use strict";var r=n(1),o=n(74),c=n.n(o);r.a.use(c.a,{easing:[.42,0,.58,1]})},194:function(t,e,n){n(195),t.exports=n(196)},260:function(t,e,n){t.exports=n.p+"img/frame.cf2009c.png"}},[[194,7,3,8]]]);