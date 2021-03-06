<template>
  <div class="app">
    <ul>
      <h2>保留中の質問</h2>
      <p v-show="!posts[0]">質問はありません</p>
      <li v-for="post in posts" :key="post.id">
        <div class="primary-post">
          <div @click="transition(post.id)" class="card-button">
            <canvas :id="post.id"></canvas>
          </div>
          <p v-html="post.answer" class="answer"></p>
        </div>
        <div
          v-for="reply in post.replies"
          :key="reply.id"
          class="secondary-post"
        >
          <canvas :id="reply.id"></canvas>
          <p v-html="reply.replyAnswer">{{ reply.replyAnswer }}</p>
        </div>
        <SharedSendSentence
          :mode="modeAnswerForKeep"
          :contentId="post.id"
          :show="true"
          :keepButton="false"
          :MICROCMS_KEY="MICROCMS_KEY"
          :CONSUMER_KEY="CONSUMER_KEY"
          :CONSUMER_KEY_SECRET="CONSUMER_KEY_SECRET"
          :ACCESS_TOKEN_KEY="ACCESS_TOKEN_KEY"
          :ACCESS_TOKEN_KEY_SECRET="ACCESS_TOKEN_KEY_SECRET"
          @get-posts="getPosts"
        />
      </li>
    </ul>
    <infinite-loading @infinite="loadNewPost">
      <div slot="spinner" class="spinner">読み込んでいます...</div>
      <div slot="no-more" class="no-more">条件に合致した質問は以上です。</div>
      <div slot="no-results" class="no-results">
        条件に合致した質問は見つかりませんでした。
      </div>
      <div slot="error" class="no-results">エラーが発生しました。</div>
    </infinite-loading>
  </div>
</template>
<script>
import Common from "~/plugins/common.js";
import InfiniteLoading from "vue-infinite-loading";
export default {
  components: {
    InfiniteLoading,
  },
  data() {
    return {
      MICROCMS_KEY: "",
      CONSUMER_KEY: "",
      CONSUMER_KEY_SECRET: "",
      ACCESS_TOKEN_KEY: "",
      ACCESS_TOKEN_KEY_SECRET: "",
      posts: [],
      modeQuestion: "question",
      modeAnswerForKeep: "answerForKeep",
      postCount: 0,
    };
  },
  methods: {
    async getPosts() {
      await this.$axios
        .$get(
          "https://q-box.microcms.io/api/v1/q_box_posts?filters=answer[not_exists]&orders=createdAt",
          {
            headers: { "X-MICROCMS-API-KEY": this.MICROCMS_KEY },
          }
        )
        .then((response) => {
          this.$set(this, "posts", response.contents);
        })
        .catch((error) => {
          alert("通信に失敗しました。：" + error);
          console.log(error);
        });
    },
    async setReply() {
      if (this.posts) {
        for (const post of this.posts) {
          await this.$axios
            .$get(
              "https://q-box.microcms.io/api/v1/q_box_replies?filters=replyFor[equals]" +
                post.id +
                "[and]replyAnswer[exists]&orders=createdAt",
              {
                headers: { "X-MICROCMS-API-KEY": this.MICROCMS_KEY },
              }
            )
            .then((response) => {
              Common.generateImage(
                document,
                response.contents,
                "replySentence",
                ""
              );
              this.$set(post, "replies", response.contents);
              Common.modifyUrlInPost(post.replies, "replyAnswer");
            })
            .catch((error) => {
              // alert('通信に失敗しました。：' + error)
              console.log(error);
            });
        }
      }
    },
    async loadNewPost($state) {
      const loadPostNumber = 10;
      await this.$axios
        .$get(
          "https://q-box.microcms.io/api/v1/q_box_posts?filters=answer[exists],state[equals]keep&limit=" +
            loadPostNumber +
            "&offset=" +
            this.postCount,
          {
            headers: { "X-MICROCMS-API-KEY": this.MICROCMS_KEY },
          }
        )
        .then((response) => {
          if (response.contents.length) {
            Common.modifyUrlInPost(response.contents, "answer");
            this.posts = this.posts.concat(response.contents);
            Common.generateImage(document, response.contents, "question", "");
            this.setReply();
            this.postCount += response.contents.length;
            $state.loaded();
          } else {
            $state.complete();
          }
        })
        .catch((error) => {
          $state.error();
          alert("通信に失敗しました。：" + error);
          console.log(error);
        });
    },
  },
  async created() {
    this.MICROCMS_KEY = process.env.MICROCMS_KEY;
    this.CONSUMER_KEY = process.env.CONSUMER_KEY;
    this.CONSUMER_KEY_SECRET = process.env.CONSUMER_KEY_SECRET;
    this.ACCESS_TOKEN_KEY = process.env.ACCESS_TOKEN_KEY;
    this.ACCESS_TOKEN_KEY_SECRET = process.env.ACCESS_TOKEN_KEY_SECRET;
    this.loadNewPost();
  },
};
</script>
<style lang="scss" scoped>
.send-sentence {
  margin: 70px auto 0;
  width: 60%;
  transition: 0s;
}
h2 {
  margin: 30px 0;
  font-size: 2.2em;
}
ul {
  width: 60%;
  margin: 0 auto;
  li {
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-bottom: 30px;
    padding: 5%;
    box-shadow: 0 0 5px 5px rgba(0, 0, 0, 0.1);
    canvas {
      width: 100%;
      border-radius: 10px;
    }
    h2 {
      font-size: 1.5em;
    }
    p {
      white-space: pre-line;
      overflow-wrap: break-word;
    }
    .primary-post {
      width: 80%;
      text-align: center;
      margin: 5px auto;
      .card-button {
        transition: 0.5s;
        cursor: pointer;
        &:hover {
          opacity: 0.7;
        }
      }
      .answer {
        width: 80%;
        margin: 10px auto;
      }
      .created-at {
        width: 100px;
        padding: 5px 10px;
        margin: 10px;
        border-radius: 5px;
        border: 2px solid rgba(67, 134, 135, 0.7);
        background-color: rgb(117, 184, 185);
        color: white;
      }
      .answered {
        background-color: rgb(0, 74, 169);
        border: 2px solid rgba(0, 24, 85, 0.7);
      }
      .keep,
      .waitInformation {
        background-color: rgb(255, 222, 103);
        border: 2px solid rgba(205, 172, 53, 0.7);
        color: #333;
      }
    }
    .secondary-post {
      width: 60%;
      text-align: center;
      margin: 5px auto;
      p {
        width: 80%;
        margin: 10px auto;
      }
    }
  }
}
.spinner {
  animation: spinner 1s infinite ease;
}
@keyframes spinner {
  0% {
    opacity: 1;
  }
  50% {
    opacity: 0;
  }
  100% {
    opacity: 1;
  }
}
.no-more,
.no-results,
.spinner {
  margin: 30px auto;
}

@media (max-width: 1024px) {
  ul {
    width: 100%;
  }
}
@media (max-width: 520px) {
  .send-sentence {
    width: 100%;
    margin: 0 !important;
  }
  ul {
    width: 100%;
    h2 {
      font-size: 1.6em;
      margin: 0 10px 10px;
    }
    li {
      width: 100%;
      padding: 20px 0;
      .primary-post {
        width: 90%;
      }
      .secondary-post {
        width: 75%;
      }
    }
  }
}
</style>
