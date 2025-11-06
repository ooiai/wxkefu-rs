use dotenvy::dotenv;
use std::env;
use wxkefu_rs::sync_msg::{MsgPayload, SyncMsgItem, SyncMsgRequest};
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Example: pull Kf messages/events via sync_msg using a short-lived callback token
    //
    // Run with:
    //   WXKF_CORP_ID=ww... \
    //   WXKF_APP_SECRET=your_kf_secret \
    //   WXKF_SYNC_TOKEN=token_from_callback_event \
    //   [optional] WXKF_OPEN_KFID=wk... \
    //   [optional] WXKF_CURSOR=prev_cursor \
    //   [optional] WXKF_LIMIT=1000 \
    //   [optional] WXKF_VOICE_FORMAT=0 \
    //   [optional] MAX_ROUNDS=5 \
    //   cargo run --example pull_messages
    //
    // Notes:
    // - WXKF_SYNC_TOKEN is recommended (from callback event); without it, the API has stricter rate limits.
    // - Keep and reuse next_cursor to continue from the last position.
    // - Cache and reuse access_token to avoid rate limiting.

    let _ = dotenv();

    // 1) Acquire access_token (WeCom/Kf)
    let corpid =
        env::var("WXKF_CORP_ID").expect("set WXKF_CORP_ID (WeCom corpid, starts with 'ww')");
    let corpsecret = env::var("WXKF_APP_SECRET")
        .expect("set WXKF_APP_SECRET (WeChat Customer Service Secret from Kf admin)");
    let client = KfClient::default();
    let token_resp = client
        .get_access_token(&Auth::WeCom {
            corp_id: corpid.clone(),
            corp_secret: corpsecret,
        })
        .await?;
    let access_token = token_resp.access_token;
    println!(
        "Got access_token (expires_in={}s). Pulling messages...",
        token_resp.expires_in
    );

    // 2) Build initial sync request
    let sync_token = env::var("WXKF_SYNC_TOKEN").ok().filter(|s| !s.is_empty());
    let open_kfid = env::var("WXKF_OPEN_KFID").ok().filter(|s| !s.is_empty());
    let cursor = env::var("WXKF_CURSOR").ok().filter(|s| !s.is_empty());
    let limit = env::var("WXKF_LIMIT")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(1000);
    let voice_format = env::var("WXKF_VOICE_FORMAT")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());

    if sync_token.is_none() {
        eprintln!(
            "Hint: WXKF_SYNC_TOKEN is not set. The sync_msg API will have stricter rate limits."
        );
    }
    if open_kfid.is_none() {
        eprintln!("Hint: WXKF_OPEN_KFID is not set. Pulling messages for all Kf accounts.");
    }
    if cursor.is_none() {
        eprintln!("Hint: WXKF_CURSOR is not set. Starting from the latest position.");
    }

    let mut req = SyncMsgRequest {
        cursor,
        token: sync_token,
        limit: Some(limit.min(1000)),
        voice_format,
        open_kfid,
    };

    // 3) Pull in a loop: continue while has_more == 1
    let max_rounds = env::var("MAX_ROUNDS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&r| r > 0)
        .unwrap_or(5);

    let mut round = 0u32;
    loop {
        round += 1;
        println!(
            "\n-- sync_msg round {} (cursor={:?}, open_kfid={:?}, limit={:?})",
            round, req.cursor, req.open_kfid, req.limit
        );

        let resp = client.sync_msg(&access_token, &req).await;

        match resp {
            Ok(ok) => {
                println!("resp:{:?}", ok);
                println!(
                    "resp: errcode={}, errmsg={}, has_more={}, next_cursor={:?}, msg_count={}",
                    ok.errcode,
                    ok.errmsg,
                    ok.has_more,
                    ok.next_cursor,
                    ok.msg_list.len()
                );
                for (i, item) in ok.msg_list.iter().enumerate() {
                    print_item(i, item);
                }

                // Update cursor and continue if has_more == 1
                req.cursor = ok.next_cursor;
                if ok.has_more == 1 && round < max_rounds {
                    continue;
                } else {
                    println!("Done. has_more={}, rounds={}", ok.has_more, round);
                    if let Some(c) = req.cursor {
                        println!("Save this next_cursor for future incremental pulls:\n{}", c);
                    }
                    break;
                }
            }
            Err(e) => {
                eprintln!("sync_msg error: {e}");
                break;
            }
        }
    }

    Ok(())
}

fn print_item(idx: usize, item: &SyncMsgItem) {
    println!(
        "  [{}] msgid={}, open_kfid={}, external_userid={:?}, send_time={}, origin={:?}",
        idx,
        item.common.msgid,
        item.common.open_kfid,
        item.common.external_userid,
        item.common.send_time,
        item.common.origin
    );

    match &item.payload {
        MsgPayload::Text { text } => {
            println!(
                "      [text] content={:?}, menu_id={:?}",
                text.content, text.menu_id
            );
        }
        MsgPayload::Image { image } => {
            println!("      [image] media_id={}", image.media_id);
        }
        MsgPayload::Voice { voice } => {
            println!("      [voice] media_id={}", voice.media_id);
        }
        MsgPayload::Video { video } => {
            println!("      [video] media_id={}", video.media_id);
        }
        MsgPayload::File { file } => {
            println!("      [file] media_id={}", file.media_id);
        }
        MsgPayload::Location { location } => {
            println!(
                "      [location] lat={}, lng={}, name={:?}, address={:?}",
                location.latitude, location.longitude, location.name, location.address
            );
        }
        MsgPayload::MiniProgram { miniprogram } => {
            println!(
                "      [miniprogram] title={:?}, appid={}, pagepath={}, thumb_media_id={}",
                miniprogram.title,
                miniprogram.appid,
                miniprogram.pagepath,
                miniprogram.thumb_media_id
            );
        }
        MsgPayload::ChannelsShopProduct {
            channels_shop_product: p,
        } => {
            println!(
                "      [channels_shop_product] product_id={}, title={:?}, sales_price={}, shop={:?}",
                p.product_id, p.title, p.sales_price, p.shop_nickname
            );
        }
        MsgPayload::ChannelsShopOrder {
            channels_shop_order: o,
        } => {
            println!(
                "      [channels_shop_order] order_id={}, titles={:?}, price_wording={}, shop={:?}",
                o.order_id, o.product_titles, o.price_wording, o.shop_nickname
            );
        }
        MsgPayload::MergedMsg { merged_msg } => {
            println!(
                "      [merged_msg] title={:?}, items={}",
                merged_msg.title,
                merged_msg.item.len()
            );
            for (j, it) in merged_msg.item.iter().enumerate() {
                // msg_content is a JSON string; print briefly
                let snippet = it.msg_content.chars().take(120).collect::<String>();
                println!(
                    "        [{}] time={}, type={}, sender={}, content_snippet={:?}...",
                    j, it.send_time, it.msgtype, it.sender_name, snippet
                );
            }
        }
        MsgPayload::Channels { channels } => {
            println!(
                "      [channels] sub_type={}, nickname={:?}, title={:?}",
                channels.sub_type, channels.nickname, channels.title
            );
        }
        MsgPayload::Note {} => {
            println!("      [note] (no additional content)");
        }
        MsgPayload::Event { event } => {
            println!(
                "      [event] type={}, open_kfid={:?}, external_userid={:?}, scene={:?}, scene_param={:?}, welcome_code={:?}, fail_msgid={:?}, fail_type={:?}, recall_msgid={:?}",
                event.event_type,
                event.open_kfid,
                event.external_userid,
                event.scene,
                event.scene_param,
                event.welcome_code,
                event.fail_msgid,
                event.fail_type,
                event.recall_msgid,
            );
            if let Some(ch) = &event.wechat_channels {
                println!(
                    "        wechat_channels: scene={}, nickname={:?}, shop_nickname={:?}",
                    ch.scene, ch.nickname, ch.shop_nickname
                );
            }
        }
    }
}
