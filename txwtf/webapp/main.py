import logging
import os
from datetime import datetime

import threading
# from threading import current_thread

from flask import (
    Blueprint, current_app, flash, redirect, render_template,
    request, send_from_directory, url_for)

from flask_login import current_user, login_required

from markdown import markdown

from . import db, remote_addr, upload_archive
from .models import (
    Emoji, HashTag, PostedMessage, PostedMessageView,
    Reaction, SystemLog, Tag, User, UserChange, UserFile,
    Attachment, Mention)


main = Blueprint('main', __name__)
logger = logging.getLogger(__name__)


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/edit-profile')
@login_required
def editprofile():
    changes = db.session.query(UserChange).filter(
        UserChange.user_id == current_user.id).order_by(
            UserChange.change_time.desc())
    return render_template(
        'editprofile.html', changes=changes)


def generate_render_post_data(dbposts):
    posts = []
    logged_in = hasattr(current_user, 'email_verified')  # janky but whatev
    class PostInfo(object):
        pass
    for dbpost in dbposts:
        post = PostInfo()
        user = db.session.query(User).filter(User.id == dbpost.user_id).first()
        post.user_id = user.id
        post.avatar_url = user.avatar_url
        post.name = user.name
        post.username = user.username
        post.email = user.email
        post.post_time = dbpost.post_time
        post.post_content = dbpost.post_content
        post.id = dbpost.id
        post.deleted = dbpost.deleted
        post.num_reposts = len(db.session.query(PostedMessage).filter(
            PostedMessage.repost_id == dbpost.id).all())
        post.replies = generate_render_post_data(
            db.session.query(PostedMessage).filter(
                PostedMessage.reply_to == dbpost.id).all())
        post.reply_to = dbpost.reply_to
        post.view_count = dbpost.view_count
        post.num_replies = len(post.replies)
        post.reactions = db.session.query(Reaction).filter(
            Reaction.post_id == dbpost.id,
            Reaction.deleted == False).all()  # noqa: E712
        post.num_reactions = len(post.reactions)
        if logged_in:
            post.current_user_reactions = db.session.query(Reaction).filter(
                Reaction.user_id == current_user.id,
                Reaction.post_id == dbpost.id,
                Reaction.deleted == False).all()  # noqa: E712

        post.repost = None
        if dbpost.repost_id:
            dbrepost = db.session.query(PostedMessage).filter(
                PostedMessage.id == dbpost.repost_id)
            post.repost = generate_render_post_data(dbrepost)[0]
            post.repost_id = dbpost.repost_id

        posts.append(post)
    return posts


def collect_post_ids(posts):
    post_ids = []
    for post in posts:
        post_ids.append(post.id)
        if post.repost:
            post_ids.append(post.repost.id)
        post_ids.extend(collect_post_ids(post.replies))
    return post_ids


def increment_posts_view_count(posts):
    """
    For every post in the list, increment the view count in the
    database and record a log of views for statistics. Also increment
    user post_view_count records.
    """
    now_time = datetime.now()
    current_user_id = None
    if hasattr(current_user, "id"):
        current_user_id = current_user.id
    user_counts = {}
    for msg in db.session.query(PostedMessage).filter(
        PostedMessage.id.in_(collect_post_ids(posts))):
        # don't count self views
        if current_user_id is not None and \
            current_user_id == msg.user_id:
            continue
        if msg.user_id not in user_counts:
            user_counts[msg.user_id] = 1
        else:
            user_counts[msg.user_id] += 1
        msg.view_count += 1
        pmv = PostedMessageView(
            post_id=msg.id,
            view_time=now_time,
            current_user=current_user_id,
            referrer=request.referrer,
            user_agent=str(request.user_agent),
            remote_addr=remote_addr(request),
            endpoint=request.endpoint)
        db.session.add(pmv)
    for user in db.session.query(User).filter(
        User.id.in_(user_counts.keys())):
        user.post_view_count += user_counts[user.id]


@main.route('/u/<username>')
@login_required
def user_view(username):
    user = db.session.query(User).filter(User.username == username).first()
    if user is None:
        return render_template('error.html', error_msg='Unknown user!')

    view = request.args.get("view", "public")

    # don't count self views
    if current_user.id != user.id:
        user.view_count += 1

    # get post messages for this user depending on the
    # view selection
    dbposts = []
    if view == "public":
        dbposts = db.session.query(PostedMessage).filter(
            PostedMessage.user_id == user.id,
            PostedMessage.reply_to == None).order_by(
                PostedMessage.post_time.desc()).all()
    elif view == "replies":
        dbposts = db.session.query(PostedMessage).filter(
            PostedMessage.user_id == user.id,
            PostedMessage.reply_to != None).order_by(
                PostedMessage.post_time.desc()).all()
    elif view == "mentions":
        dbposts = db.session.query(PostedMessage).join(
            Mention, PostedMessage.id == Mention.post_id).filter(
                Mention.user_id == user.id).order_by(
                    PostedMessage.post_time.desc()).all()
    # TODO: need "private" view once we add followers and
    # friends user distinction

    posts = generate_render_post_data(dbposts)
    increment_posts_view_count(posts)
    db.session.commit()
    return render_template(
        'users.html', user=user, posts=posts, view=view)


@main.route('/user-list')
@login_required
def user_list():
    return render_template(
        'userlist.html',
        users=db.session.query(User).order_by(
            User.post_view_count.desc()).all())


@main.route('/system-log')
@login_required
def system_log():
    if not current_user.is_admin:
        return render_template('unauthorized.html'), 401
    logs = db.session.query(SystemLog).order_by(SystemLog.event_time.desc())
    return render_template('systemlog.html', logs=logs)


@main.route('/about')
def about():
    return render_template('about.html')


_renderPostTL = threading.local()
def render_post(
        post, show_level_menu=True, show_delete_button=True,
        show_repost=True, show_replies=True, show_deleted_replies=False,
        max_depth=3):
    local_depth = getattr(_renderPostTL, 'depth', None)
    if local_depth is None:
        _renderPostTL.depth = 0
        local_depth = 0
    _renderPostTL.depth = local_depth + 1
    if _renderPostTL.depth > max_depth:
        retval = ""
    else:
        retval = render_template(
            'post_fragment.html', post=post,
            show_level_menu=show_level_menu,
            show_delete_button=show_delete_button,
            show_repost=show_repost, show_replies=show_replies,
            show_deleted_replies=show_deleted_replies)
    _renderPostTL.depth = local_depth
    return retval


def render_posts(
        posts, show_post_message_button=True,
        show_repost=True, show_level_menu=True, show_deleted=False,
        show_replies=True, show_deleted_replies=False,
        show_delete_button=True,
        show_top_level_replies=True,
        max_depth=2):
    return render_template(
        'posts_fragment.html', posts=posts,
        show_level_menu=show_level_menu,
        show_delete_button=show_delete_button,
        show_post_message_button=show_post_message_button,
        show_deleted=show_deleted, show_replies=show_replies,
        show_deleted_replies=show_deleted_replies,
        show_repost=show_repost,
        show_top_level_replies=show_top_level_replies,
        max_depth=max_depth)


def render_post_message(post_content="", redirect_url="/posts"):
    return render_template(
        'post_message_fragment.html',
        post_content=post_content, redirect_url=redirect_url)


def render_user_card(user):
    return render_template('user_card_fragment.html', user=user)


@main.route('/posts')
def posts():
    # TODO: paginate post rendering by limiting
    # range of posts to render by min/max time
    dbposts = db.session.query(PostedMessage).order_by(
        PostedMessage.post_time.desc())
    posts = generate_render_post_data(dbposts)
    dbtags = db.session.query(Tag).order_by(
        Tag.last_used_time.desc()).all()
    tags = []

    class TagInfo():
        pass
    for dbtag in dbtags:
        tag = TagInfo()
        tag.name = dbtag.name
        tag.last_used_time = dbtag.last_used_time
        tag.count = len(
            db.session.query(HashTag).filter(
                HashTag.tag_id == dbtag.id).all())
        tags.append(tag)
    increment_posts_view_count(posts)
    db.session.commit()
    return render_template(
        'posts.html', posts=posts, tags=tags)


@main.route('/p/<post_id>')
def post_view(post_id):
    dbposts = db.session.query(PostedMessage).filter(
        PostedMessage.id == int(post_id)).all()
    if len(dbposts) == 0:
        return render_template(
            'error.html', error_msg='Unknown post!')
    posts = generate_render_post_data(dbposts)
    dbreposts = db.session.query(PostedMessage).filter(
        PostedMessage.repost_id == int(post_id)).order_by(
        PostedMessage.post_time.desc()).all()
    reposts = generate_render_post_data(dbreposts)
    increment_posts_view_count(posts)
    increment_posts_view_count(reposts)
    db.session.commit()
    return render_template(
        'post_view.html', posts=posts, reposts=reposts)


@main.route('/h/<name>')
def hash_tag_view(name):
    dbtag = db.session.query(Tag).filter(Tag.name == name).first()
    if not dbtag:
        return render_template(
            'error.html', error_msg='Unknown hash tag!')
    dbposts = db.session.query(PostedMessage).join(
        HashTag, PostedMessage.id == HashTag.post_id).filter(
            HashTag.tag_id == dbtag.id).order_by(
                PostedMessage.post_time.desc()).all()
    posts = generate_render_post_data(dbposts)
    increment_posts_view_count(posts)
    db.session.commit()
    description = "{} (last used {})".format(
        dbtag.tag_description, dbtag.last_used_time.ctime())
    return render_template(
        'post_view.html', posts=posts, title="#{}".format(name),
        description=description)


def scrape_hashtags(content):
    textList = content.split()
    hashtags = set()
    for i in textList:
        if i[0] == "#":
            x = i.replace("#", '')
            # TODO: make sure hashtags are valid C identifiers
            # as our standard
            if len(x) == 0:
                continue
            hashtags.add(x)
    return list(hashtags)


def scrape_mentions(content):
    textList = content.split()
    mentions = set()
    for i in textList:
        if i[0] == "@":
            mention = i.replace("@", '')
            if len(mention) == 0:
                continue

            # TODO: scan for valid mention strings so we
            # can capture mentions next to period's and 
            # other punctuation.

            user = db.session.query(User).filter(
                User.username == mention).first()
            if user is None:
                # if no such user by mention username then
                # just skip it
                continue

            mentions.add((mention, user.id))
    return list(mentions)


def add_reaction(user_id, post_id, reaction_name):
    now = datetime.now()
    user = db.session.query(User).filter(User.id == user_id).first()
    if not user:
        logger.error("Invalid user {}".format(user_id))
        return
    emoji = db.session.query(Emoji).filter(Emoji.name == reaction_name).first()
    if not emoji:
        # TODO: choose a better default url
        # TODO: add a routine to populate the emoji table with a default
        # set of emojis
        emoji = Emoji(
            added_time=now, user_id=user_id, name=reaction_name,
            emoji_url="/assets/img/cropped-atxcf_logo_small-32x32.jpg",
            emoji_description=reaction_name,
            modified_time=now)
        db.session.add(emoji)
        new_log = SystemLog(
            event_code=31337,  # default for now
            event_time=now,
            event_desc="User {} Adding emoji {}".format(
                user.name, reaction_name),
            referrer=request.referrer,
            user_agent=str(request.user_agent),
            remote_addr=remote_addr(request),
            endpoint=request.endpoint)
        db.session.add(new_log)
        db.session.commit()

    # don't do anything if this reaction was already saved
    reaction = db.session.query(Reaction).filter(
        Reaction.user_id == user_id,
        Reaction.post_id == post_id,
        Reaction.emoji_id == emoji.id).first()
    if reaction is not None:
        if not reaction.deleted:
            logger.warning(
                "Already recorded user {} reaction {} for post {}".format(
                    user_id, reaction_name, post_id))
            return
        else:
            reaction.deleted = False
    else:
        reaction = Reaction(
            user_id=user_id, post_id=post_id, reaction_time=now,
            emoji_id=emoji.id, deleted=False)
        db.session.add(reaction)
    log_reaction = UserChange(
        user_id=user_id,
        change_code=31337,
        change_time=now,
        change_desc="Adding {} reaction to post {}".format(
            reaction_name, post_id),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint)
    db.session.add(log_reaction)
    db.session.commit()

    # Return the posts total number of reactions
    return len(db.session.query(Reaction).filter(
        Reaction.post_id == post_id,
        Reaction.emoji_id == emoji.id,
        Reaction.deleted == False).all())  # noqa: E712


def remove_reaction(user_id, post_id, reaction_name):
    emoji = db.session.query(Emoji).filter(Emoji.name == reaction_name).first()
    if not emoji:
        logger.warning("No emoji {}".format(reaction_name))
        return
    reaction = db.session.query(Reaction).filter(
        Reaction.emoji_id == emoji.id,
        Reaction.user_id == user_id,
        Reaction.post_id == post_id).first()
    if not reaction:
        logger.warning("No reaction {} by user {} for post {}".format(
            reaction_name, user_id, post_id))
        return
    if reaction.deleted:
        logger.warning(
            "Reaction {} by user {} for post {} already removed".format(
                reaction_name, user_id, post_id))
        return
    reaction.deleted = True
    log_reaction = UserChange(
        user_id=user_id,
        change_code=31337,
        change_time=datetime.now(),
        change_desc="Removing {} reaction to post {}".format(
            reaction_name, post_id),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint)
    db.session.add(log_reaction)
    db.session.commit()

    # Return the posts total number of reactions
    return len(db.session.query(Reaction).filter(
        Reaction.post_id == post_id,
        Reaction.emoji_id == emoji.id,
        Reaction.deleted == False).all())  # noqa: E712


@main.route('/add-reaction', methods=['POST'])
@login_required
def post_add_reaction():
    post_id = request.form.get('post_id')
    reaction_name = request.form.get('reaction_name')
    user_id = current_user.id
    return str(add_reaction(user_id, post_id, reaction_name))


@main.route('/remove-reaction', methods=['POST'])
@login_required
def post_remove_reaction():
    post_id = request.form.get('post_id')
    reaction_name = request.form.get('reaction_name')
    user_id = current_user.id
    return str(remove_reaction(user_id, post_id, reaction_name))


@main.route('/post-message', methods=['POST'])
@login_required
def post_message():
    redirect_url = request.form.get('redirect')
    reply_to = request.form.get('reply_to')
    repost_id = request.form.get('repost_id')
    if reply_to == "":
        reply_to = None
    if repost_id == "":
        repost_id = None

    # extract all hash tags and add them to the tables
    markdown_content = request.form.get('post_content')
    hashtags = scrape_hashtags(markdown_content)
    mentions = scrape_mentions(markdown_content)

    # replace hashtags with links to hashtag page
    for hashtag in hashtags:
        markdown_content = markdown_content.replace(
            "#{}".format(hashtag),
            "[#{}](/h/{})".format(hashtag, hashtag))

    # TODO: for some reason the above breaks being able to click on the
    # post and go to its post page

    # replace mentions with links to user page
    for username, _ in mentions:
        markdown_content = markdown_content.replace(
            "@{}".format(username),
            "[@{}](/u/{})".format(username, username))

    post_content = markdown(markdown_content)
    if len(post_content) == 0:
        flash('Error: Empty post!')
        return redirect(redirect_url)

    # TODO: extract all emoji strings and replace them with inline
    # images in the post_content after generating html from markdown

    # TODO: we should do validation on the reply_to and repost_ids
    # to make sure that this user has access to the post when we
    # introduce the concept of follows and friends and the post is
    # flagged private

    msg = PostedMessage(
        user_id=current_user.id,
        post_time=datetime.now(),
        post_content=post_content,
        reply_to=reply_to,
        repost_id=repost_id,
        deleted=False,
        view_count=0)
    db.session.add(msg)
    db.session.commit()
    flash("Message posted!")

    current_user.post_count += 1

    for hashtag in hashtags:
        # if the tag doesn't exist, add it to the db and attribute it
        # to the current_user. Then add a hashtag entry for this post.
        now = datetime.now()
        dbtag = db.session.query(Tag).filter(
            Tag.name == hashtag).first()
        if dbtag is None:
            new_tag = Tag(
                name=hashtag,
                created_time=now,
                user_id=current_user.id,
                tag_description="#{}".format(hashtag),
                modified_time=now,
                last_used_time=now)
            db.session.add(new_tag)
            db.session.commit()
            dbtag = new_tag

        dbtag.last_used_time = now
        new_hashtag = HashTag(
            post_id=msg.id,
            tag_id=dbtag.id,
            post_time=now)
        db.session.add(new_hashtag)

    for username, user_id in mentions:
        new_ment = Mention(
            user_id=user_id,
            post_id=msg.id)
        db.session.add(new_ment)

    db.session.commit()

    return redirect(redirect_url)


@main.route('/delete-post', methods=['POST'])
@login_required
def delete_post():
    post_id = request.form.get('post_id')
    post = db.session.query(PostedMessage).filter(
        PostedMessage.id == int(post_id)).first()
    if post.user_id != current_user.id:
        logger.error("Unauthorized post delete: {} {}".format(
            post.user_id, current_user.id))
        return render_template(
            'error.html', error_msg="Unauthorized post delete"), 401
    post.deleted = True
    new_change = UserChange(
        user_id=current_user.id,
        change_code=31337,  # default for now
        change_time=datetime.now(),
        change_desc="deleted post {}".format(post.id),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint)
    db.session.add(new_change)
    new_log = SystemLog(
        event_code=31337,  # default for now
        event_time=datetime.now(),
        event_desc="User {} deleted post {}".format(
            current_user.email, post.id),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint)
    db.session.add(new_log)
    db.session.commit()
    return "OK"


@main.route('/assets/<path:path>')
def assets(path):
    return send_from_directory('assets', path)


@main.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(main.root_path, 'assets', 'img'),
        'cropped-atxcf_logo_small-32x32.jpg')


@main.route("/upload-avatar", methods=['POST'])
@login_required
def upload_avatar():
    if "avatar" in request.files:
        if request.files["avatar"].filename == "":
            flash("Null upload!!1")
            return redirect(url_for("main.editprofile"))
        saved_name = upload_archive.save(
            request.files["avatar"],
            folder=str(current_user.username))
        current_user.avatar_url = "/uploads/{}".format(
            saved_name)
        current_user.modified_time = datetime.now()
        new_change = UserChange(
            user_id=current_user.id,
            change_code=31337,  # default for now
            change_time=datetime.now(),
            change_desc="Changing avatar to: {}".format(saved_name),
            referrer=request.referrer,
            user_agent=str(request.user_agent),
            remote_addr=remote_addr(request),
            endpoint=request.endpoint)
        db.session.add(new_change)
        new_log = SystemLog(
            event_code=31337,  # default for now
            event_time=datetime.now(),
            event_desc="User {} Uploaded {}".format(
                current_user.email, saved_name),
            referrer=request.referrer,
            user_agent=str(request.user_agent),
            remote_addr=remote_addr(request),
            endpoint=request.endpoint)
        db.session.add(new_log)
        db.session.commit()
        flash("Avatar saved successfully as {}.".format(
            saved_name))
        logger.info("Changing user {} avatar image to: {}".format(
            current_user.email, saved_name))
        return redirect(url_for("main.editprofile"))
    else:
        flash("Invalid request")
        return redirect(url_for("main.editprofile"))


@main.route("/upload-header-image", methods=['POST'])
@login_required
def upload_header_image():
    if "header_image" in request.files:
        if request.files["header_image"].filename == "":
            flash("Null upload!!1")
            return redirect(url_for("main.editprofile"))
        saved_name = upload_archive.save(
            request.files["header_image"],
            folder=str(current_user.username))
        current_user.header_image_url = "/uploads/{}".format(
            saved_name)
        current_user.modified_time = datetime.now()
        new_change = UserChange(
            user_id=current_user.id,
            change_code=31337,  # default for now
            change_time=datetime.now(),
            change_desc="Changing header to: {}".format(saved_name),
            referrer=request.referrer,
            user_agent=str(request.user_agent),
            remote_addr=remote_addr(request),
            endpoint=request.endpoint)
        db.session.add(new_change)
        new_log = SystemLog(
            event_code=31337,  # default for now
            event_time=datetime.now(),
            event_desc="Uploaded {}".format(saved_name),
            referrer=request.referrer,
            user_agent=str(request.user_agent),
            remote_addr=remote_addr(request),
            endpoint=request.endpoint)
        db.session.add(new_log)
        db.session.commit()
        flash("Header image saved successfully as {}.".format(
            saved_name))
        logger.info("Changing user {} header image to: {}".format(
            current_user.email, saved_name))
        return redirect(url_for("main.editprofile"))
    else:
        flash("Invalid request")
        return redirect(url_for("main.editprofile"))


@main.route("/upload-card-image", methods=['POST'])
@login_required
def upload_card_image():
    if "card_image" in request.files:
        if request.files["card_image"].filename == "":
            flash("Null upload!!1")
            return redirect(url_for("main.editprofile"))
        saved_name = upload_archive.save(
            request.files["card_image"],
            folder=str(current_user.username))
        current_user.card_image_url = "/uploads/{}".format(
            saved_name)
        current_user.modified_time = datetime.now()
        new_change = UserChange(
            user_id=current_user.id,
            change_code=31337,  # default for now
            change_time=datetime.now(),
            change_desc="Changing card image to: {}".format(saved_name),
            referrer=request.referrer,
            user_agent=str(request.user_agent),
            remote_addr=remote_addr(request),
            endpoint=request.endpoint)
        db.session.add(new_change)
        new_log = SystemLog(
            event_code=31337,  # default for now
            event_time=datetime.now(),
            event_desc="Uploaded {}".format(saved_name),
            referrer=request.referrer,
            user_agent=str(request.user_agent),
            remote_addr=remote_addr(request),
            endpoint=request.endpoint)
        db.session.add(new_log)
        db.session.commit()
        flash("Card image saved successfully as {}.".format(
            saved_name))
        logger.info("Changing user {} card image to: {}".format(
            current_user.email, saved_name))
        return redirect(url_for("main.editprofile"))
    else:
        flash("Invalid request")
        return redirect(url_for("main.editprofile"))


@main.route("/update-user-description", methods=['POST'])
@login_required
def update_user_description():
    desc = request.form.get('user_description')

    # replace hashtags with links to hashtag page
    for hashtag in scrape_hashtags(desc):
        dbht = db.session.query(Tag).filter(
            Tag.name == hashtag).first()
        if dbht is None:
            continue  # ignore if no tag exists
        desc = desc.replace(
            "#{}".format(hashtag),
            "[#{}](/h/{})".format(hashtag, hashtag))

    current_user.description = markdown(desc)
    current_user.modified_time = datetime.now()
    new_change = UserChange(
        user_id=current_user.id,
        change_code=31337,  # default for now
        change_time=datetime.now(),
        change_desc="Changing description to: {}".format(desc),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint)
    db.session.add(new_change)
    db.session.commit()
    logger.info("Changing user {} description to: {}".format(
        current_user.email, desc))
    return redirect(url_for("main.editprofile"))


@main.route("/update-user-name", methods=['POST'])
@login_required
def update_user_name():
    name = request.form.get('name')
    current_user.name = name
    current_user.modified_time = datetime.now()
    new_change = UserChange(
        user_id=current_user.id,
        change_code=31337,  # default for now
        change_time=datetime.now(),
        change_desc="Changing name to: {}".format(name),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint)
    db.session.add(new_change)
    db.session.commit()
    logger.info("Changing user {} name to: {}".format(
        current_user.email, name))
    return redirect(url_for("main.editprofile"))


@main.route("/update-user-header-text", methods=['POST'])
@login_required
def update_user_header_text():
    header_text = request.form.get('user_header_text')

    # replace hashtags with links to hashtag page
    for hashtag in scrape_hashtags(header_text):
        dbht = db.session.query(Tag).filter(
            Tag.name == hashtag).first()
        if dbht is None:
            continue  # ignore if no tag exists
        header_text = header_text.replace(
            "#{}".format(hashtag),
            "[#{}](/h/{})".format(hashtag, hashtag))

    current_user.header_text = markdown(header_text)
    current_user.modified_time = datetime.now()
    new_change = UserChange(
        user_id=current_user.id,
        change_code=31337,  # default for now
        change_time=datetime.now(),
        change_desc="Changing header text to: {}".format(header_text),
        referrer=request.referrer,
        user_agent=str(request.user_agent),
        remote_addr=remote_addr(request),
        endpoint=request.endpoint)
    db.session.add(new_change)
    db.session.commit()
    logger.info("Changing user {} header text to: {}".format(
        current_user.email, header_text))
    return redirect(url_for("main.editprofile"))


@main.route('/uploads/<path:path>')
def uploads(path):
    return send_from_directory(
        current_app.config["UPLOADED_ARCHIVE_DEST"], path)


@main.route("/upload-file", methods=['POST'])
@login_required
def upload_file():
    name = request.form.get('name')
    description = request.form.get('description')
    if "user_file" in request.files:
        if request.files["user_file"].filename == "":
            flash("Null upload!!1")
            return redirect(url_for("main.user_files"))
        saved_name = upload_archive.save(
            request.files["user_file"],
            folder=str(current_user.username))
        user_file = UserFile(
            name=name,
            file_path=saved_name,
            preview_path=None,  # TODO: generate preview
            description=description,
            now=datetime.now(),
            user_id=current_user.id,
            deleted=False,
            view_count=0)
        db.session.add(user_file)
        db.session.commit()
    else:
        flash("Invalid request")
        return redirect(url_for("main.user_files"))
